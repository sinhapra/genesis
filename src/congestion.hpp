#pragma once
#include "transport.hpp"
#include <deque>

namespace ufcp {
struct RateSample {
    uint64_t acked = 0, lost = 0, delivered = 0, prior = 0;
    Time rtt = 0, newest_sent = 0;
    double rate = 0;
    bool limited = false;
};
// Requirement: sample delivery snapshots over both send and ACK phases, with bounded attempt retention.
class DeliverySampler {
    struct Snapshot {
        uint64_t delivered, bytes;
        Time sent, first_send, delivered_at;
        unsigned epoch;
        bool limited, flight = true, lost = false;
    };
    std::map<uint64_t, Snapshot> packets_;
    uint64_t delivered_ = 0, flight_ = 0, limited_until_ = 0;
    Time first_send_ = 0, delivered_at_ = 0;
    unsigned epoch_ = 0;
public:
    uint64_t flight() const { return flight_; }
    uint64_t delivered() const { return delivered_; }
    size_t history_size() const { return packets_.size(); }
    void limited() { limited_until_ = std::max<uint64_t>(1, delivered_ + flight_); }
    void restart(Time now) { ++epoch_; first_send_ = delivered_at_ = now; limited_until_ = 0; }
    RateSample process(const std::vector<Event>& events) {
        RateSample result;
        Snapshot chosen{}; bool candidate = false;
        Time ack_at = 0;
        for (auto event : events) {
            if (event.kind == Event::Sent) {
                for (auto it = packets_.begin(); packets_.size() >= HISTORY && it != packets_.end();) {
                    if (!it->second.flight) it = packets_.erase(it); else ++it;
                }
                require(packets_.size() < HISTORY && !packets_.count(event.number), "sampler history exhausted or repeated send");
                if (packets_.empty()) first_send_ = delivered_at_ = event.at;
                packets_.emplace(event.number, Snapshot{delivered_, event.bytes, event.sent, first_send_, delivered_at_, epoch_, limited_until_ != 0, true});
                flight_ += event.bytes;
                continue;
            }
            auto it = packets_.find(event.number);
            if (it == packets_.end()) continue;
            auto& packet = it->second;
            if (packet.flight) { flight_ -= packet.bytes; packet.flight = false; }
            if (event.kind == Event::Lost) {
                if (!packet.lost) result.lost += packet.bytes;
                packet.lost = true; continue;
            }
            result.acked += packet.bytes; delivered_ += packet.bytes; ack_at = event.at;
            Time rtt = event.at - packet.sent;
            if (rtt > 0 && (!result.rtt || rtt < result.rtt)) result.rtt = rtt;
            if (packet.epoch == epoch_ && (!candidate || packet.sent >= chosen.sent)) { chosen = packet; candidate = true; }
            result.newest_sent = std::max(result.newest_sent, packet.sent);
            packets_.erase(it);
        }
        result.delivered = delivered_;
        if (candidate) {
            // Use the slower phase so compressed ACK bursts cannot inflate the bandwidth estimate.
            Time interval = std::max(chosen.sent - chosen.first_send, ack_at - chosen.delivered_at);
            if (interval > 0) result.rate = double(delivered_ - chosen.delivered) * 1000000.0 / double(interval);
            result.prior = chosen.delivered; result.limited = chosen.limited;
            first_send_ = std::max(first_send_, chosen.sent);
        }
        if (result.acked) delivered_at_ = ack_at;
        if (limited_until_ && delivered_ > limited_until_) limited_until_ = 0;
        return result;
    }
};

// Requirement: userspace BBR-inspired control is independent of kernel TCP BBR and transport reliability.
class CongestionController {
public:
    enum class Mode { Startup, Drain, ProbeBW, ProbeRTT };
    static constexpr double INITIAL_RATE = 81920, MIN_RATE = 16384, MAX_RATE = 100000000;
private:
    DeliverySampler sampler_;
    uint64_t maximum_, minimum_, cwnd_, round_end_ = 0;
    unsigned round_ = 0, plateau_ = 0, phase_ = 0;
    Mode mode_ = Mode::Startup;
    std::deque<std::pair<unsigned, double>> bandwidth_;
    double estimate_ = 0, full_bandwidth_ = 0, rate_ = INITIAL_RATE, rate_cap_ = MAX_RATE, flight_cap_;
    uint64_t round_acked_ = 0, round_lost_ = 0, losses_ = 0;
    Time min_rtt_ = 100000, min_stamp_, phase_at_, probe_done_ = 0, probe_min_ = 0;
    Time last_feedback_, last_sent_, last_loss_, last_silence_, last_now_;
    bool rtt_known_ = false, idle_ = false;
    void clock(Time now) { require(now >= last_now_, "nonmonotonic controller clock"); last_now_ = now; }
    double bdp() const { return std::max<double>(minimum_, (estimate_ ? estimate_ : INITIAL_RATE) * double(min_rtt_) / 1000000); }
    void enter(Mode mode, Time now) { mode_ = mode; phase_at_ = now; phase_ = 0; }
    void output() {
        static constexpr double gains[] = {1.2, .8, 1, 1, 1, 1, 1, 1};
        double gain = mode_ == Mode::Startup ? 2 : mode_ == Mode::Drain ? .7 : mode_ == Mode::ProbeBW ? gains[phase_] : 1;
        double model = estimate_ ? estimate_ : INITIAL_RATE / 2;
        rate_ = std::clamp(std::min(model * gain, rate_cap_), MIN_RATE, MAX_RATE);
        double target = mode_ == Mode::ProbeRTT ? double(minimum_) : 2 * bdp() + 2 * PAYLOAD;
        uint64_t cap = uint64_t(std::clamp(std::min(target, flight_cap_), double(minimum_), double(maximum_)));
        cwnd_ = std::min(cwnd_, cap);
    }
    void congestion(Time now, uint64_t before_loss) {
        if (now - last_loss_ < std::max<Time>(min_rtt_, 50000)) return;
        last_loss_ = now;
        // Requirement: stale bandwidth maxima cannot sustain overload after excessive loss or a capacity drop.
        rate_cap_ = std::max(MIN_RATE, std::min(rate_cap_, rate_) * .7);
        flight_cap_ = std::max<double>(minimum_, std::min<double>(flight_cap_, std::max<uint64_t>(before_loss, cwnd_)) * .7);
        if (mode_ != Mode::ProbeRTT) enter(Mode::Drain, now);
        plateau_ = 0;
    }
public:
    explicit CongestionController(size_t window = 32, Time now = 0)
        : maximum_(window * PAYLOAD), minimum_(std::min<size_t>(window, 4) * PAYLOAD),
          cwnd_(std::min<size_t>(window, 8) * PAYLOAD), flight_cap_(double(maximum_)),
          min_stamp_(now), phase_at_(now), last_feedback_(now), last_sent_(now),
          last_loss_(now - 10000000), last_silence_(now), last_now_(now) {
        require(window && window <= MAX_CHUNKS, "invalid controller window"); output();
    }
    Mode mode() const { return mode_; }
    unsigned phase() const { return phase_; }
    double bandwidth() const { return estimate_; }
    double pacing_rate() const { return rate_; }
    Time min_rtt() const { return rtt_known_ ? min_rtt_ : 0; }
    uint64_t window() const { return cwnd_; }
    uint64_t losses() const { return losses_; }
    const DeliverySampler& sampler() const { return sampler_; }
    const char* mode_name() const {
        return mode_ == Mode::Startup ? "startup" : mode_ == Mode::Drain ? "drain" : mode_ == Mode::ProbeBW ? "probe-bw" : "probe-rtt";
    }
    Budget budget() const { return {cwnd_, std::max<Time>(1, Time(std::ceil(PAYLOAD * 1000000.0 / rate_)))}; }
    void feedback(const std::vector<Event>& events, Time now) {
        clock(now);
        for (auto event : events) if (event.kind == Event::Sent) { last_sent_ = now; idle_ = false; }
        auto sample = sampler_.process(events);
        losses_ += sample.lost;
        round_acked_ += sample.acked; round_lost_ += sample.lost;
        if (sample.lost && double(round_lost_) / double(std::max<uint64_t>(1, round_lost_ + round_acked_)) > .02)
            congestion(now, sampler_.flight() + sample.lost);
        if (!sample.acked) { output(); return; }
        last_feedback_ = last_silence_ = now;
        if (sample.rtt && (!rtt_known_ || sample.rtt < min_rtt_)) {
            min_rtt_ = sample.rtt; min_stamp_ = now; rtt_known_ = true;
        }
        if (mode_ == Mode::ProbeRTT && sample.newest_sent >= phase_at_ && sample.rtt)
            probe_min_ = probe_min_ ? std::min(probe_min_, sample.rtt) : sample.rtt;
        bool new_round = sample.rate > 0 && sample.prior >= round_end_;
        if (new_round) {
            round_end_ = sample.delivered + sampler_.flight();
            if (!sample.limited) ++round_;
        }
        // Requirement: limited samples may raise the bandwidth model but cannot lower it or end startup.
        if (sample.rate > 0 && (!sample.limited || sample.rate >= estimate_)) {
            if (!bandwidth_.empty() && bandwidth_.back().first == round_) bandwidth_.back().second = std::max(bandwidth_.back().second, sample.rate);
            else bandwidth_.push_back({round_, sample.rate});
            while (!bandwidth_.empty() && bandwidth_.front().first + 10 <= round_) bandwidth_.pop_front();
            estimate_ = 0;
            for (auto value : bandwidth_) estimate_ = std::max(estimate_, value.second);
            estimate_ = std::min(estimate_, MAX_RATE);
        }
        if (new_round && !sample.limited) {
            if (mode_ == Mode::Startup) {
                if (estimate_ >= full_bandwidth_ * 1.25) { full_bandwidth_ = estimate_; plateau_ = 0; }
                else if (++plateau_ >= 3) enter(Mode::Drain, now);
            }
            if (!round_lost_) {
                rate_cap_ = std::min(MAX_RATE, rate_cap_ * 1.1);
                flight_cap_ = std::min<double>(maximum_, flight_cap_ + PAYLOAD);
            }
            round_acked_ = round_lost_ = 0;
        }
        uint64_t growth = std::min<uint64_t>(sample.acked, maximum_);
        cwnd_ = std::min(maximum_, cwnd_ + growth); output();
    }
    void tick(Time now, bool active, bool limited) {
        clock(now);
        if (limited) sampler_.limited();
        // Requirement: restart idle flows conservatively and invalidate delivery intervals across idle epochs.
        if (!active && !sampler_.flight() && !idle_ && now - last_sent_ >= std::max<Time>(min_rtt_, 200000)) {
            idle_ = true; sampler_.restart(now); cwnd_ = std::min<uint64_t>(maximum_, 8 * PAYLOAD);
            rate_cap_ = std::min(rate_cap_, INITIAL_RATE); enter(Mode::Startup, now); full_bandwidth_ = 0; plateau_ = 0;
            last_feedback_ = last_silence_ = now;
        }
        if (!idle_ && active && sampler_.flight() && now - last_feedback_ >= std::max<Time>(500000, 3 * min_rtt_) &&
            now - last_silence_ >= std::max<Time>(500000, 3 * min_rtt_)) {
            last_silence_ = now; rate_cap_ = std::max(MIN_RATE, std::min(rate_cap_, rate_) * .5);
            cwnd_ = minimum_; enter(Mode::Drain, now);
        }
        if (mode_ == Mode::Drain && sampler_.flight() <= bdp()) enter(Mode::ProbeBW, now);
        if (mode_ == Mode::ProbeBW && now - phase_at_ >= std::max<Time>(min_rtt_, 10000)) {
            phase_ = (phase_ + 1) % 8; phase_at_ = now;
        }
        // Requirement: age minimum RTT and briefly drain before accepting an upward RTT refresh.
        if (rtt_known_ && active && !idle_ && mode_ != Mode::ProbeRTT && now - min_stamp_ >= 10000000) {
            enter(Mode::ProbeRTT, now); probe_done_ = 0; probe_min_ = 0;
        }
        if (mode_ == Mode::ProbeRTT && sampler_.flight() <= minimum_) {
            if (!probe_done_) probe_done_ = now + 200000;
            if (now >= probe_done_ && probe_min_) { min_rtt_ = probe_min_; min_stamp_ = now; enter(Mode::ProbeBW, now); }
        }
        output();
    }
};
}
