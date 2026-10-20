#include "../src/file_io.hpp"
#include <fcntl.h>
#include <iostream>
#include <random>
#include <deque>

using namespace ufcp;
void check(bool condition) {
    require(condition, "transport test assertion failed");
}
template <class F> void fails(F operation) {
    bool failed = false;
    try {
        operation();
    } catch (const std::runtime_error&) {
        failed = true;
    }
    check(failed);
}
Bytes bytes(size_t n = PAYLOAD, uint8_t value = 42) {
    return Bytes(n, value);
}
void accounting() {
    Sender sender(PAYLOAD, PAYLOAD);
    sender.queue(bytes());
    Transmission original, retry;
    check(sender.next(0, original));
    check(sender.flight_bytes() == PAYLOAD);
    check(!sender.next(999999, retry));
    check(sender.next(1000000, retry));
    check(original.number != retry.number && original.offset == retry.offset);
    check(sender.flight_bytes() == PAYLOAD);
    check(sender.acknowledge({PAYLOAD, 0, {{original.number, original.number}}}, 1001000));
    check(sender.complete() && sender.delivered() == PAYLOAD && sender.flight_bytes() == PAYLOAD);
    check(sender.acknowledge({PAYLOAD, 0, {{original.number, original.number}}}, 1002000));
    check(sender.flight_bytes() == PAYLOAD && sender.delivered() == PAYLOAD);
    check(sender.acknowledge({PAYLOAD, 0, {{retry.number, retry.number}}}, 1003000));
    check(!sender.flight_bytes() && sender.delivered() == PAYLOAD);
    unsigned delivered = 0, losses = 0;
    for (auto event : sender.events()) {
        delivered += event.newly_delivered;
        losses += event.kind == Event::Lost;
    }
    check(delivered == 1 && losses == 1);
    fails([&] { sender.tick(1); });
    std::cout << "PASS per-attempt flight accounting and late ACKs\n";
}
void malformed() {
    Sender sender(2 * PAYLOAD, 0);
    sender.queue(bytes());
    Transmission value;
    check(!sender.next(0, value));
    check(!sender.acknowledge({2 * PAYLOAD, 0, {{1, 1}}}, 1));
    check(sender.receive_limit() == 0 && sender.delivered() == 0);
    check(sender.acknowledge({PAYLOAD, 0, {}}, 2));
    check(sender.next(2, value));
    for (auto ack : std::vector<Ack>{{2 * PAYLOAD, 0, {{1, 2}}},
                                     {2 * PAYLOAD, 0, {{1, 1}, {1, 1}}},
                                     {2 * PAYLOAD, 25001, {{1, 1}}},
                                     {2 * PAYLOAD + 1, 0, {{1, 1}}}}) {
        check(!sender.acknowledge(ack, 3));
        check(sender.receive_limit() == PAYLOAD && sender.flight_bytes() == PAYLOAD);
    }
    Ack decoded;
    auto good = ack_packet(7, {PAYLOAD, 5000, {{1, 1}}});
    check(decode_ack(good, decoded));
    for (size_t n = 0; n < good.size(); ++n)
        check(!decode_ack(Bytes(good.begin(), good.begin() + n), decoded));
    auto rewrite = [](Bytes& b) { put(b, 26, wire_crc(b), 4); };
    auto bad = good;
    bad[HEADER + 13] = 33;
    rewrite(bad);
    check(!decode_ack(bad, decoded));
    bad = good;
    put(bad, HEADER + 14, 2, 8);
    rewrite(bad);
    check(!decode_ack(bad, decoded));
    bad = good;
    bad[5] = 1;
    rewrite(bad);
    check(!valid(bad));
    bad = good;
    bad[3] = '2';
    rewrite(bad);
    check(!valid(bad));
    bad = good;
    bad.back() ^= 1;
    check(!valid(bad));
    bad = good;
    bad.resize(MAX_DATAGRAM + 1);
    check(!valid(bad));
    fails([&] { get(good, good.size(), 1); });
    std::cout << "PASS malformed ACK atomicity, wire lengths, CRC, and version\n";
}
void receiving() {
    Receiver receiver(3 * PAYLOAD + 7, 2);
    check(!receiver.accept({1, 1, bytes()}, 0));
    check(!receiver.accept({1, UINT64_MAX, bytes()}, 0));
    check(!receiver.accept({0, 0, bytes()}, 0));
    check(!receiver.accept({1, 0, bytes(1)}, 0));
    check(!receiver.accept({1, 2 * PAYLOAD, bytes()}, 0));
    check(receiver.accept({2, PAYLOAD, bytes()}, 0));
    check(!receiver.accept({2, 0, bytes()}, 0));
    check(!receiver.accept({UINT64_MAX, 0, bytes()}, 0));
    check(!receiver.ack_due(4999));
    check(receiver.ack_due(5000));
    auto ack = receiver.ack(5000);
    check(ack.ranges.size() == 1 && ack.ranges[0].low == 2);
    check(receiver.accept({1, 0, bytes()}, 6000));
    check(receiver.buffered_chunks() == 2 && receiver.limit() == 2 * PAYLOAD);
    check(!receiver.accept({3, PAYLOAD, bytes(PAYLOAD, 1)}, 6000));
    fails([&] { receiver.consume(1, 6000); });
    receiver.consume(2 * PAYLOAD, 7000);
    check(receiver.limit() == 3 * PAYLOAD + 7 && receiver.buffered_chunks() == 0 &&
          receiver.ack_due(7000));
    check(receiver.accept({3, 2 * PAYLOAD, bytes()}, 8000));
    check(receiver.accept({4, 3 * PAYLOAD, bytes(7)}, 8000));
    receiver.consume(3 * PAYLOAD + 7, 9000);
    check(receiver.complete());
    check(receiver.accept({5, 0, bytes()}, 10000));
    Receiver zero(PAYLOAD, 0);
    check(!zero.accept({1, 0, bytes()}, 0));
    zero.capacity(1, 1);
    check(zero.ack(1).limit == PAYLOAD);
    fails([&] { zero.capacity(0, 2); });
    Receiver history(PAYLOAD, 1);
    for (uint64_t i = 1; i <= HISTORY * 2; ++i)
        check(history.accept({i * 2, 0, bytes()}, Time(i)));
    ack = history.ack(HISTORY * 2);
    check(history.receipt_count() == HISTORY && ack.ranges.size() == MAX_RANGES &&
          history.buffered_chunks() == 1);
    std::cout
        << "PASS reassembly, slow consumption, final chunks, zero capacity, and ACK retention\n";
}
void zero_credit_and_timers() {
    Sender sender(PAYLOAD, 0);
    sender.queue(bytes());
    Transmission packet;
    check(!sender.next(0, packet));
    check(!sender.probe(199999));
    check(sender.probe(200000));
    check(!sender.probe(399999));
    check(sender.probe(400000));
    check(sender.acknowledge({PAYLOAD, 0, {}}, 401000));
    check(sender.next(401000, packet));
    check(sender.acknowledge({PAYLOAD, 0, {{1, 1}}}, 451000));
    check(sender.rto() == 150000);
    Sender silent(PAYLOAD, 0);
    silent.queue(bytes());
    for (Time t = 0; t < SILENCE; t += 1000000) {
        check(silent.acknowledge({0, 0, {}}, t));
        silent.tick(t);
    }
    fails([&] { silent.tick(SILENCE); });
    Sender idle(PAYLOAD, PAYLOAD);
    idle.tick(SILENCE * 10);
    idle.queue(bytes());
    check(idle.next(SILENCE * 10 + 1, packet));
    Sender pacing(2 * PAYLOAD, 2 * PAYLOAD);
    pacing.queue(bytes());
    pacing.queue(bytes());
    check(pacing.next(0, packet));
    check(!pacing.next(999, packet));
    check(pacing.next(1000, packet));
    Sender controlled(2 * PAYLOAD, 2 * PAYLOAD);
    controlled.queue(bytes());
    controlled.queue(bytes());
    controlled.budget({PAYLOAD, 100});
    check(controlled.next(0, packet));
    check(!controlled.next(1000, packet));
    check(controlled.acknowledge({2 * PAYLOAD, 0, {{packet.number, packet.number}}}, 1001));
    check(controlled.next(1001, packet));
    Sender fast(2 * PAYLOAD, 2 * PAYLOAD);
    fast.queue(bytes());
    fast.queue(bytes());
    fast.budget({2 * PAYLOAD, 100});
    check(fast.next(0, packet));
    check(fast.wait(1) == 99);
    check(!fast.next(99, packet));
    check(fast.next(100, packet));
    Sender stable(200 * PAYLOAD, 200 * PAYLOAD, 1);
    Time clock = 0;
    for (unsigned i = 0; i < 100; ++i) {
        stable.queue(bytes());
        check(stable.next(clock, packet));
        check(stable.acknowledge({200 * PAYLOAD, 0, {{packet.number, packet.number}}},
                                 clock + 80000));
        stable.events();
        clock += 81000;
    }
    check(stable.rto() >= 80000 + MAX_ACK_DELAY);
    stable.queue(bytes());
    check(stable.next(clock, packet));
    stable.events();
    stable.tick(clock + 100000);
    check(stable.events().empty() && stable.flight_bytes() == PAYLOAD);
    check(stable.acknowledge({200 * PAYLOAD, 0, {{packet.number, packet.number}}},
                             clock + 100000));
    for (auto event : stable.events())
        check(event.kind != Event::Lost);
    Sender initial(PAYLOAD, PAYLOAD);
    initial.queue(bytes());
    check(initial.next(0, packet));
    initial.events();
    initial.tick(205000);
    check(initial.events().empty() && initial.flight_bytes() == PAYLOAD);
    check(initial.acknowledge({PAYLOAD, 0, {{packet.number, packet.number}}}, 205000));
    Sender tunnel(PAYLOAD, PAYLOAD);
    tunnel.reliable_link(true);
    tunnel.budget({PAYLOAD, 0});
    tunnel.queue(bytes());
    check(tunnel.next(0, packet));
    check(!tunnel.next(1000000, packet));
    check(!tunnel.probe(1000000));
    check(!tunnel.data_available(1000000) && tunnel.wait(1000000) == 1000 &&
          tunnel.flight_bytes() == PAYLOAD);
    check(tunnel.acknowledge({PAYLOAD, 0, {{packet.number, packet.number}}}, 1200000));
    for (auto event : tunnel.events())
        check(event.kind != Event::Lost);
    check(tunnel.complete() && !tunnel.flight_bytes());
    std::cout << "PASS pacing, adaptive RTO, feedback silence, credit probes, and idle producer\n";
}
void simulation(unsigned seed) {
    constexpr uint64_t total = 6 * 1024 * 1024 + 19;
    Sender sender(total, 4 * PAYLOAD, 32);
    Receiver receiver(total, 4);
    std::mt19937 random(seed);
    struct Delivery {
        Time at;
        Transmission packet;
    };
    struct Feedback {
        Time at;
        Ack ack;
    };
    std::deque<Delivery> network;
    std::deque<Feedback> feedback;
    uint64_t produced = 0, consumed = 0;
    size_t max_history = 0;
    for (Time now = 0; now < 300000000 && !sender.complete(); now += 1000) {
        while (sender.can_queue()) {
            size_t length = size_t(std::min<uint64_t>(PAYLOAD, total - produced));
            sender.queue(bytes(length, uint8_t(produced / PAYLOAD)));
            produced += length;
        }
        Transmission outgoing;
        if (sender.next(now, outgoing) && random() % 7) {
            network.push_back({now + Time(random() % 40000), outgoing});
            if (!(random() % 5))
                network.push_back({now + 300000, outgoing});
        }
        if (sender.probe(now))
            receiver.probe(now);
        for (auto it = network.begin(); it != network.end();) {
            if (it->at > now) {
                ++it;
                continue;
            }
            receiver.accept(it->packet, now);
            it = network.erase(it);
        }
        if (now % 9000 == 0) {
            if (auto data = receiver.peek(consumed)) {
                check(*data == bytes(data->size(), uint8_t(consumed / PAYLOAD)));
                consumed += data->size();
                receiver.consume(consumed, now);
            }
        }
        if (receiver.ack_due(now)) {
            Ack ack = receiver.ack(now);
            if (random() % 5)
                feedback.push_back({now + Time(random() % 40000), ack});
        }
        for (auto it = feedback.begin(); it != feedback.end();) {
            if (it->at > now) {
                ++it;
                continue;
            }
            check(sender.acknowledge(it->ack, now));
            it = feedback.erase(it);
        }
        sender.events();
        max_history = std::max(max_history, sender.history_size());
        check(sender.history_size() <= HISTORY && sender.pending_size() <= 32 &&
              receiver.buffered_chunks() <= 4);
        check(sender.flight_bytes() <= 32 * PAYLOAD && sender.delivered() <= produced);
    }
    check(sender.complete() && sender.delivered() == total && max_history == HISTORY);
    while (const Bytes* data = receiver.peek(consumed)) {
        consumed += data->size();
        receiver.consume(consumed, 300000000);
    }
    check(receiver.complete() && consumed == total);
    std::cout << "PASS deterministic loss/reordering/burst/slow-consumer simulation seed " << seed
              << '\n';
}
void file_workers() {
    int fd = open("/dev/full", O_WRONLY);
    check(fd >= 0);
    bool failed = false;
    {
        FileWriter writer(fd, 0);
        check(writer.push(bytes()));
        writer.close();
        for (unsigned i = 0; i < 1000; ++i) {
            try {
                writer.done();
            } catch (const std::runtime_error&) {
                failed = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    close(fd);
    check(failed);
    struct stat original {};
    original.st_size = PAYLOAD;
    failed = false;
    {
        FileReader reader(-1, original, 0);
        for (unsigned i = 0; i < 1000; ++i) {
            try {
                reader.done();
            } catch (const std::runtime_error&) {
                failed = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    check(failed);
    FileQueue queue;
    for (size_t i = 0; i < FileQueue::CAPACITY; ++i)
        check(queue.try_push(bytes()));
    check(!queue.try_push(bytes()));
    std::atomic<bool> exited{false};
    std::thread blocked([&] {
        check(!queue.push(bytes()));
        exited.store(true);
    });
    queue.cancel();
    blocked.join();
    check(exited.load());
    std::cout << "PASS disk-full/read-error propagation and bounded-queue cancellation\n";
}
int main() {
    try {
        accounting();
        malformed();
        receiving();
        zero_credit_and_timers();
        for (unsigned seed : {7u, 91u, 2026u})
            simulation(seed);
        file_workers();
        std::cout << "All deterministic transport tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
