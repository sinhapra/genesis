#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <vector>

namespace ufcp {
using Bytes = std::vector<uint8_t>;
using Time = int64_t;
constexpr size_t PAYLOAD = 1024, MAX_CHUNKS = 8192, HISTORY = 32768, MAX_RANGES = 32;
constexpr Time MAX_ACK_DELAY = 25000, SILENCE = 10000000;
inline void require(bool ok, const char* message) {
    if (!ok)
        throw std::runtime_error(message);
}
struct Range {
    uint64_t low, high;
};
struct Ack {
    uint64_t limit = 0;
    Time delay = 0;
    std::vector<Range> ranges;
};
struct Transmission {
    uint64_t number, offset;
    Bytes data;
};
struct Event {
    enum Kind { Sent, Acknowledged, Lost } kind;
    uint64_t number, offset, bytes;
    Time sent, at;
    bool newly_delivered = false;
};
struct Budget {
    uint64_t flight_bytes = 32 * PAYLOAD;
    Time interval = 1000;
};

// Requirement: isolate reliability and flow control behind an explicitly injected monotonic clock.
class Sender {
    struct Chunk {
        Bytes data;
        unsigned attempts = 0;
        Time last = 0;
    };
    struct Attempt {
        uint64_t offset, bytes;
        Time sent;
        bool flight = true, acked = false;
    };
    uint64_t total_, queued_ = 0, limit_, next_ = 1, flight_ = 0, delivered_ = 0, sent_ = 0;
    size_t window_;
    // Logical chunks survive retries; each network attempt has its own congestion and ACK accounting.
    std::map<uint64_t, Chunk> chunks_;
    std::map<uint64_t, Attempt> history_;
    std::set<uint64_t> flying_;
    std::vector<Event> events_;
    Budget budget_;
    Time next_send_ = 0, progress_ = 0, probe_at_ = 200000, probe_backoff_ = 200000;
    Time rto_ = 1000000, last_now_ = 0;
    double srtt_ = 0, variance_ = 0;
    bool reliable_link_ = false;
    void clock(Time now) {
        require(now >= last_now_, "nonmonotonic transport clock");
        last_now_ = now;
    }
    void event(Event value) {
        require(events_.size() < HISTORY * 3, "transport feedback events must be drained");
        events_.push_back(value);
    }
    void retire() {
        for (auto it = history_.begin(); history_.size() >= HISTORY && it != history_.end();) {
            if (!it->second.flight)
                it = history_.erase(it);
            else
                ++it;
        }
        require(history_.size() < HISTORY, "active packet history exhausted");
    }
    Time timeout(const Chunk& chunk) const {
        return std::min<Time>(2000000, rto_ * (int64_t(1) << std::min<unsigned>(
                                                   chunk.attempts ? chunk.attempts - 1 : 0, 5)));
    }

  public:
    Sender(uint64_t total, uint64_t initial_limit, size_t window = 32, Time now = 0)
        : total_(total), limit_(initial_limit), window_(window), progress_(now),
          probe_at_(now + 200000), last_now_(now) {
        require(window && window <= MAX_CHUNKS && initial_limit <= total,
                "invalid sender configuration");
        budget_.flight_bytes = window * PAYLOAD;
    }
    void budget(Budget value) {
        require(value.flight_bytes && value.flight_bytes <= MAX_CHUNKS * PAYLOAD &&
                    value.interval >= 0,
                "invalid send budget");
        budget_ = value;
    }
    // Requirement: SSH/TCP supplies loss recovery; preserve flow ACKs without nested retransmission timers.
    void reliable_link(bool enabled) {
        require(history_.empty(), "link mode must be selected before sending");
        reliable_link_ = enabled;
    }
    bool can_queue() const {
        return queued_ < total_ && chunks_.size() < window_;
    }
    void queue(Bytes data) {
        require(can_queue() && data.size() == std::min<uint64_t>(PAYLOAD, total_ - queued_),
                "invalid producer chunk");
        chunks_.emplace(queued_, Chunk{std::move(data), 0, 0});
        queued_ += chunks_.rbegin()->second.data.size();
    }
    bool complete() const {
        return queued_ == total_ && chunks_.empty();
    }
    uint64_t delivered() const {
        return delivered_;
    }
    uint64_t flight_bytes() const {
        return flight_;
    }
    uint64_t sent_bytes() const {
        return sent_;
    }
    uint64_t receive_limit() const {
        return limit_;
    }
    size_t history_size() const {
        return history_.size();
    }
    size_t pending_size() const {
        return chunks_.size();
    }
    Time rto() const {
        return rto_;
    }
    bool data_available(Time now) const {
        for (const auto& entry : chunks_) {
            const auto& chunk = entry.second;
            if (reliable_link_ && chunk.attempts)
                continue;
            if (entry.first <= limit_ && chunk.data.size() <= limit_ - entry.first &&
                (!chunk.attempts || now - chunk.last >= timeout(chunk)))
                return true;
        }
        return false;
    }
    // Requirement: let the socket adapter honor submillisecond pacing without busy polling.
    Time wait(Time now) const {
        Time delay = 1000;
        for (const auto& entry : chunks_) {
            const auto& chunk = entry.second;
            if (reliable_link_ && chunk.attempts)
                continue;
            if (entry.first > limit_ || chunk.data.size() > limit_ - entry.first ||
                flight_ > budget_.flight_bytes ||
                chunk.data.size() > budget_.flight_bytes - flight_)
                continue;
            Time ready = chunk.attempts ? chunk.last + timeout(chunk) : now;
            delay = std::min(delay, std::max<Time>(0, std::max(ready, next_send_) - now));
        }
        if (!reliable_link_ && !chunks_.empty())
            delay = std::min(delay, std::max<Time>(0, probe_at_ - now));
        return delay;
    }
    std::vector<Event> events() {
        std::vector<Event> result;
        result.swap(events_);
        return result;
    }
    // Requirement: local producer starvation must not be misclassified as lost network feedback.
    void tick(Time now) {
        clock(now);
        bool waiting = !chunks_.empty();
        if (!waiting)
            progress_ = now;
        require(!waiting || now - progress_ < SILENCE,
                reliable_link_ ? "SSH flow-control acknowledgement timeout"
                               : "UDP acknowledgement timeout");
        if (reliable_link_)
            return;
        for (auto it = flying_.begin(); it != flying_.end();) {
            uint64_t number = *it;
            auto& attempt = history_.at(number);
            // Attempts are in send order and every loss threshold is at least rto_.
            if (now - attempt.sent < rto_)
                break;
            auto chunk = chunks_.find(attempt.offset);
            Time threshold = chunk == chunks_.end() ? rto_ : timeout(chunk->second);
            if (attempt.flight && now - attempt.sent >= threshold) {
                attempt.flight = false;
                flight_ -= attempt.bytes;
                event(
                    {Event::Lost, number, attempt.offset, attempt.bytes, attempt.sent, now, false});
                it = flying_.erase(it);
            } else
                ++it;
        }
    }
    bool next(Time now, Transmission& out) {
        tick(now);
        if (now < next_send_)
            return false;
        for (auto& entry : chunks_) {
            auto& chunk = entry.second;
            if (entry.first > limit_ || chunk.data.size() > limit_ - entry.first)
                continue;
            if (flight_ > budget_.flight_bytes ||
                chunk.data.size() > budget_.flight_bytes - flight_)
                continue;
            if (chunk.attempts && (reliable_link_ || now - chunk.last < timeout(chunk)))
                continue;
            require(chunk.attempts < 11, "UDP retry limit exceeded");
            require(next_ != UINT64_MAX, "packet number exhausted");
            retire();
            uint64_t number = next_++;
            history_.emplace(number, Attempt{entry.first, chunk.data.size(), now, true, false});
            flying_.insert(number);
            flight_ += chunk.data.size();
            sent_ += chunk.data.size();
            ++chunk.attempts;
            chunk.last = now;
            // Keep the pacing schedule on its own timeline so loop overhead is not lost; allow at most
            // four intervals of catch-up so an idle or slow loop cannot release a large burst.
            next_send_ = std::max(next_send_, now - 4 * budget_.interval) + budget_.interval;
            out = {number, entry.first, chunk.data};
            event({Event::Sent, number, entry.first, chunk.data.size(), now, now, false});
            return true;
        }
        return false;
    }
    // Requirement: validate the entire ACK before changing credit, delivery, or flight accounting.
    bool acknowledge(const Ack& ack, Time now) {
        clock(now);
        if (ack.limit > total_ || ack.delay < 0 || ack.delay > MAX_ACK_DELAY ||
            ack.ranges.size() > MAX_RANGES)
            return false;
        uint64_t previous = 0;
        for (auto range : ack.ranges) {
            if (!range.low || range.low > range.high || range.high >= next_ ||
                (previous && range.low <= previous + 1))
                return false;
            previous = range.high;
        }
        bool progress = ack.limit > limit_;
        limit_ = std::max(limit_, ack.limit);
        for (auto range : ack.ranges) {
            for (auto it = history_.lower_bound(range.low);
                 it != history_.end() && it->first <= range.high;) {
                auto& attempt = it->second;
                if (attempt.acked) {
                    ++it;
                    continue;
                }
                attempt.acked = true;
                progress = true;
                if (attempt.flight) {
                    attempt.flight = false;
                    flight_ -= attempt.bytes;
                    flying_.erase(it->first);
                }
                bool unique = chunks_.erase(attempt.offset) != 0;
                if (unique)
                    delivered_ += attempt.bytes;
                // Requirement: attempt numbers make RTT samples unambiguous even for retransmitted bytes.
                double sample = double(now - attempt.sent);
                if (sample > 0) {
                    if (!srtt_) {
                        srtt_ = sample;
                        variance_ = sample / 2;
                    } else {
                        variance_ = .75 * variance_ + .25 * std::abs(srtt_ - sample);
                        srtt_ = .875 * srtt_ + .125 * sample;
                    }
                    // Requirement: allow bounded ACK delay and scheduling jitter before declaring timeout loss.
                    rto_ = Time(std::clamp(srtt_ + std::max(double(MAX_ACK_DELAY), 4 * variance_),
                                           50000.0, 2000000.0));
                }
                event({Event::Acknowledged, it->first, attempt.offset, attempt.bytes, attempt.sent,
                       now, unique});
                // Acknowledged attempts need no further accounting; later ACKs then skip them.
                it = history_.erase(it);
            }
        }
        if (progress) {
            progress_ = now;
            probe_backoff_ = 200000;
            probe_at_ = now + probe_backoff_;
        }
        return true;
    }
    // Requirement: explicit probes recover silence and zero credit without retransmitting application bytes.
    bool probe(Time now) {
        tick(now);
        if (reliable_link_)
            return false;
        if (complete() || chunks_.empty() || now < probe_at_)
            return false;
        probe_at_ = now + probe_backoff_;
        probe_backoff_ = std::min<Time>(2000000, probe_backoff_ * 2);
        return true;
    }
};

class Receiver {
    uint64_t total_, consumed_ = 0, capacity_;
    std::map<uint64_t, Bytes> buffered_;
    std::map<uint64_t, uint64_t> receipts_;
    std::map<uint64_t, uint64_t> ranges_;
    size_t pending_ack_ = 0;
    Time ack_at_ = 0, first_ack_ = 0, last_now_ = 0;
    void clock(Time now) {
        require(now >= last_now_, "nonmonotonic transport clock");
        last_now_ = now;
    }
    void schedule(Time now, bool immediate) {
        if (!pending_ack_) {
            first_ack_ = now;
            ack_at_ = now + 5000;
        }
        ++pending_ack_;
        if (immediate || pending_ack_ >= 2)
            ack_at_ = now;
    }
    // Coalesce receipts on arrival so each ACK costs O(MAX_RANGES) rather than O(HISTORY).
    void note(uint64_t number) {
        auto next = ranges_.upper_bound(number);
        if (next != ranges_.begin()) {
            auto previous = std::prev(next);
            if (previous->second >= number)
                return;
            if (previous->second + 1 == number) {
                previous->second = number;
                if (next != ranges_.end() && next->first == number + 1) {
                    previous->second = next->second;
                    ranges_.erase(next);
                }
                return;
            }
        }
        if (next != ranges_.end() && next->first == number + 1) {
            uint64_t high = next->second;
            ranges_.erase(next);
            ranges_.emplace(number, high);
        } else
            ranges_.emplace(number, number);
        while (ranges_.size() > 2 * MAX_RANGES)
            ranges_.erase(ranges_.begin());
    }

  public:
    Receiver(uint64_t total, size_t capacity_chunks = 64)
        : total_(total), capacity_(capacity_chunks * PAYLOAD) {
        require(capacity_chunks <= MAX_CHUNKS, "invalid receive capacity");
    }
    uint64_t consumed() const {
        return consumed_;
    }
    uint64_t limit() const {
        return consumed_ + std::min(capacity_, total_ - consumed_);
    }
    size_t buffered_chunks() const {
        return buffered_.size();
    }
    size_t receipt_count() const {
        return receipts_.size();
    }
    bool complete() const {
        return consumed_ == total_;
    }
    void capacity(size_t chunks, Time now) {
        clock(now);
        require(chunks <= MAX_CHUNKS && chunks * PAYLOAD >= capacity_,
                "receive capacity cannot shrink");
        capacity_ = chunks * PAYLOAD;
        schedule(now, true);
    }
    bool accept(const Transmission& packet, Time now) {
        clock(now);
        auto offset = packet.offset;
        // Requirement: stream size fixes final-chunk length and excludes overlapping or overflowing ranges.
        if (!packet.number || packet.number == UINT64_MAX || offset >= total_ || offset % PAYLOAD ||
            packet.data.size() != std::min<uint64_t>(PAYLOAD, total_ - offset))
            return false;
        auto receipt = receipts_.find(packet.number);
        if (receipt != receipts_.end() && receipt->second != offset)
            return false;
        if (offset >= consumed_) {
            if (offset > limit() || packet.data.size() > limit() - offset)
                return false;
            auto it = buffered_.find(offset);
            if (it != buffered_.end() && it->second != packet.data)
                return false;
            buffered_.emplace(offset, packet.data);
        } else if (packet.data.size() > consumed_ - offset)
            return false;
        receipts_.emplace(packet.number, offset);
        note(packet.number);
        if (receipts_.size() > HISTORY)
            receipts_.erase(receipts_.begin());
        schedule(now, false);
        return true;
    }
    const Bytes* peek(uint64_t offset) const {
        auto it = buffered_.find(offset);
        return it == buffered_.end() ? nullptr : &it->second;
    }
    // Requirement: retain accepted bytes and withhold credit until ordered consumer confirmation.
    void consume(uint64_t through, Time now) {
        clock(now);
        require(through >= consumed_ && through <= total_, "invalid consumer confirmation");
        bool changed = through != consumed_;
        while (consumed_ < through) {
            auto it = buffered_.find(consumed_);
            require(it != buffered_.end() && it->second.size() <= through - consumed_,
                    "noncontiguous consumer confirmation");
            consumed_ += it->second.size();
            buffered_.erase(it);
        }
        if (changed)
            schedule(now, true);
    }
    void probe(Time now) {
        clock(now);
        schedule(now, true);
    }
    bool ack_due(Time now) const {
        return pending_ack_ && now >= ack_at_;
    }
    Ack ack(Time now) {
        clock(now);
        Ack result;
        result.limit = limit();
        result.delay = pending_ack_ ? std::min(MAX_ACK_DELAY, now - first_ack_) : 0;
        auto first =
            ranges_.size() > MAX_RANGES ? std::prev(ranges_.end(), MAX_RANGES) : ranges_.begin();
        for (auto it = first; it != ranges_.end(); ++it)
            result.ranges.push_back({it->first, it->second});
        pending_ack_ = 0;
        return result;
    }
};
} // namespace ufcp
