#include "../src/congestion.hpp"
#include <iostream>
#include <queue>
#include <random>
#include <fstream>
#include <array>

using namespace ufcp;
void check(bool value, const char* why) {
    require(value, why);
}
Event sent(uint64_t number, Time at) {
    return {Event::Sent, number, (number - 1) * PAYLOAD, PAYLOAD, at, at, false};
}
Event acked(uint64_t number, Time at, Time send, bool unique = true) {
    return {Event::Acknowledged, number, (number - 1) * PAYLOAD, PAYLOAD, send, at, unique};
}
void sampler_tests() {
    DeliverySampler sampler;
    sampler.process({sent(1, 0), sent(2, 10000)});
    auto first = sampler.process({acked(1, 100000, 0)});
    check(first.rate == 10240, "first delivery snapshot");
    sampler.process({sent(3, 110000), sent(4, 120000)});
    auto compressed = sampler.process(
        {acked(2, 120001, 10000), acked(3, 120001, 110000), acked(4, 120001, 120000)});
    check(compressed.rate < 30000 && compressed.rate > 20000,
          "ACK compression must include send phase");
    check(sampler.process({acked(4, 120002, 120000)}).acked == 0, "duplicate ACK sampling");
    sampler.limited();
    sampler.process({sent(5, 130000)});
    check(sampler.process({acked(5, 150000, 130000)}).limited, "limited snapshot propagation");
    sampler.process({sent(6, 160000)});
    sampler.process({{Event::Lost, 6, 0, PAYLOAD, 160000, 200000, false}});
    check(!sampler.process({{Event::Lost, 6, 0, PAYLOAD, 160000, 200001, false}}).lost,
          "duplicate loss sampling");
    check(!sampler.flight(), "loss releases sampler flight");
    auto late = sampler.process({acked(6, 210000, 160000, false)});
    check(late.acked == PAYLOAD && !sampler.flight(),
          "late redundant ACK measures network delivery once");
    for (uint64_t n = 7; n < 9000; ++n) {
        sampler.process({sent(n, Time(n * 100000))});
        sampler.process(
            {{Event::Lost, n, 0, PAYLOAD, Time(n * 100000), Time(n * 100000 + 1), false}});
        check(sampler.history_size() <= HISTORY, "sampler memory bound");
    }
    sampler.restart(1000000000);
    check(!sampler.process({acked(8999, 1000000001, 899900000)}).rate, "old epoch sample rejected");
    std::cout << "PASS delivery snapshots, ACK compression, limited samples, late ACKs, bounded "
                 "history\n";
}
Time clean_round(CongestionController& cc, uint64_t& number, Time now, Time rtt = 20000,
                 bool limited = false) {
    cc.tick(now, true, limited);
    std::vector<Event> sends, acks;
    for (unsigned i = 0; i < 4; ++i) {
        sends.push_back(sent(++number, now + i * 1000));
        acks.push_back(acked(number, now + rtt + 3000, now + i * 1000));
    }
    cc.feedback(sends, now + 3000);
    cc.feedback(acks, now + rtt + 3000);
    cc.tick(now + rtt + 3000, true, false);
    return now + rtt + 4000;
}
void state_tests() {
    CongestionController cc;
    uint64_t number = 0;
    Time now = 0;
    for (unsigned i = 0; i < 9; ++i)
        now = clean_round(cc, number, now);
    check(cc.mode() == CongestionController::Mode::ProbeBW, "startup plateau and drain exit");
    double known = cc.bandwidth();
    for (unsigned i = 0; i < 12; ++i)
        now = clean_round(cc, number, now, 100000, true);
    check(cc.bandwidth() >= known, "limited samples cannot erase bandwidth estimate");
    auto phase = cc.phase();
    cc.tick(now + 200000, true, false);
    now += 200000;
    check(cc.phase() != phase, "bandwidth probe phase advance");
    double rate = cc.pacing_rate();
    uint64_t window = cc.window();
    cc.feedback({sent(++number, now)}, now);
    cc.feedback({{Event::Lost, number, 0, PAYLOAD, now, now + 100000, false}}, now + 100000);
    now += 100000;
    check(cc.pacing_rate() < rate && cc.window() <= window, "loss must lower load");
    cc.tick(now + 11000000, true, false);
    now += 11000000;
    check(cc.mode() == CongestionController::Mode::ProbeRTT, "aged minimum RTT refresh");
    now = clean_round(cc, number, now, 200000);
    cc.tick(now + 250000, true, false);
    now += 250000;
    check(cc.min_rtt() >= 200000 && cc.mode() == CongestionController::Mode::ProbeBW,
          "probe RTT supports upward refresh");
    cc.tick(now + 1000000, false, true);
    check(cc.pacing_rate() <= CongestionController::INITIAL_RATE && cc.window() <= 8 * PAYLOAD,
          "conservative idle restart");
    CongestionController silent;
    silent.feedback({sent(1, 0)}, 0);
    silent.tick(600000, true, false);
    check(silent.window() <= 4 * PAYLOAD &&
              silent.pacing_rate() < CongestionController::INITIAL_RATE,
          "feedback silence reduction");
    CongestionController limited;
    number = 0;
    now = 0;
    for (unsigned i = 0; i < 12; ++i)
        now = clean_round(limited, number, now, 20000, true);
    check(limited.mode() == CongestionController::Mode::Startup,
          "limited rounds must not declare full bandwidth");
    std::cout << "PASS startup/drain/probing, limited handling, loss, RTT aging, idle and feedback "
                 "silence\n";
}

struct LinkResult {
    double goodput, max_queue, loss_fraction;
};
// Requirement: exercise the real transport and controller against a deterministic finite bottleneck queue.
LinkResult link_test(const char* name, bool changes, bool compressed) {
    // Long enough to include the second ProbeRTT after the RTT increase at 14 seconds.
    constexpr uint64_t total = 8 * 1024 * 1024;
    Sender sender(total, 256 * PAYLOAD, 256);
    Receiver receiver(total, 256);
    CongestionController cc(256);
    struct Data {
        Time at;
        Transmission packet;
    };
    struct Feedback {
        Time at;
        Ack ack;
    };
    std::deque<Data> network;
    std::deque<Feedback> feedback;
    double departure = 0, max_queue = 0;
    uint64_t sends = 0, drops = 0;
    Time finished = 0;
    double reduced_rate = 0;
    unsigned reduced_samples = 0;
    std::ofstream trace(std::string("tests/") + name + ".csv");
    trace << "time_s,capacity_Bps,pacing_Bps,bandwidth_Bps,cwnd_bytes,flight_bytes,queue_ms,"
             "delivered_bytes,loss_bytes,mode\n";
    for (Time now = 0; now <= 90000000; now += 250) {
        double capacity = changes && now >= 4000000 && now < 10000000 ? 120000 : 480000;
        Time propagation = changes && now >= 14000000 ? 40000 : 20000;
        while (sender.can_queue())
            sender.queue(Bytes(PAYLOAD, uint8_t(sender.delivered() / PAYLOAD)));
        cc.tick(now, sender.pending_size() != 0,
                !sender.data_available(now) && sender.flight_bytes() < cc.window());
        sender.budget(cc.budget());
        Transmission packet;
        if (sender.next(now, packet)) {
            ++sends;
            double start = std::max<double>(now, departure);
            double queue = start - now;
            max_queue = std::max(max_queue, queue);
            if (queue > 60000)
                ++drops;
            else {
                departure = start + packet.data.size() * 1000000.0 / capacity;
                network.push_back({Time(departure) + propagation, packet});
            }
        }
        if (sender.probe(now))
            receiver.probe(now);
        cc.feedback(sender.events(), now);
        if (changes && now >= 7000000 && now < 9000000) {
            reduced_rate += cc.pacing_rate();
            ++reduced_samples;
        }
        for (auto it = network.begin(); it != network.end();) {
            if (it->at > now) {
                ++it;
                continue;
            }
            receiver.accept(it->packet, now);
            it = network.erase(it);
        }
        uint64_t consumed = receiver.consumed();
        while (auto bytes = receiver.peek(consumed))
            consumed += bytes->size();
        receiver.consume(consumed, now);
        if (receiver.ack_due(now)) {
            Time arrival = now + propagation;
            if (compressed)
                arrival = ((arrival + 19999) / 20000) * 20000;
            feedback.push_back({arrival, receiver.ack(now)});
        }
        for (auto it = feedback.begin(); it != feedback.end();) {
            if (it->at > now) {
                ++it;
                continue;
            }
            check(sender.acknowledge(it->ack, now), "valid simulated ACK");
            it = feedback.erase(it);
        }
        cc.feedback(sender.events(), now);
        check(cc.window() >= PAYLOAD && cc.window() <= 256 * PAYLOAD &&
                  cc.sampler().history_size() <= HISTORY,
              "controller bounds");
        check(std::isfinite(cc.pacing_rate()) && cc.pacing_rate() >= CongestionController::MIN_RATE,
              "finite pacing");
        if (now % 100000 == 0)
            trace << double(now) / 1e6 << ',' << capacity << ',' << cc.pacing_rate() << ','
                  << cc.bandwidth() << ',' << cc.window() << ',' << sender.flight_bytes() << ','
                  << std::max(0.0, departure - now) / 1000 << ',' << sender.delivered() << ','
                  << cc.losses() << ',' << cc.mode_name() << '\n';
        if (sender.complete()) {
            finished = now;
            break;
        }
    }
    check(finished && receiver.complete() && sender.delivered() == total,
          "bottleneck simulation completion");
    LinkResult result{double(total) * 1e6 / finished, max_queue / 1000,
                      double(drops) / std::max<uint64_t>(1, sends)};
    check(result.goodput > 90000 && result.max_queue < 100, "bounded queue and useful utilization");
    check(result.loss_fraction < .05, "excessive simulated queue drops");
    if (changes) {
        check(reduced_samples && reduced_rate / reduced_samples < 180000,
              "respond to fourfold capacity drop");
        check(cc.min_rtt() >= 70000 && cc.bandwidth() > 200000,
              "RTT refresh and capacity recovery");
    } else
        check(result.goodput > 360000, "stable path utilization");
    std::cout << "PASS " << name << " goodput=" << result.goodput
              << "B/s max-queue=" << result.max_queue << "ms dropped=" << result.loss_fraction * 100
              << "%\n";
    return result;
}
void competing_flows() {
    constexpr uint64_t total = 2 * 1024 * 1024;
    std::array<Sender, 2> senders{Sender(total, 256 * PAYLOAD, 256),
                                  Sender(total, 256 * PAYLOAD, 256)};
    std::array<Receiver, 2> receivers{Receiver(total, 256), Receiver(total, 256)};
    std::array<CongestionController, 2> controllers{CongestionController(256),
                                                    CongestionController(256)};
    struct Data {
        Time at;
        unsigned flow;
        Transmission packet;
    };
    struct Feedback {
        Time at;
        unsigned flow;
        Ack ack;
    };
    std::deque<Data> network;
    std::deque<Feedback> feedback;
    double departure = 0, fairness = 0;
    bool measured = false;
    for (Time now = 0; now < 60000000; now += 250) {
        for (unsigned k = 0; k < 2; ++k) {
            unsigned flow = (k + unsigned(now / 250)) % 2;
            auto& sender = senders[flow];
            auto& cc = controllers[flow];
            while (sender.can_queue())
                sender.queue(Bytes(PAYLOAD));
            cc.tick(now, sender.pending_size() != 0,
                    !sender.data_available(now) && sender.flight_bytes() < cc.window());
            sender.budget(cc.budget());
            Transmission packet;
            if (sender.next(now, packet)) {
                double start = std::max<double>(now, departure);
                if (start - now <= 60000) {
                    departure = start + PAYLOAD * 1000000.0 / 400000;
                    network.push_back({Time(departure) + 20000, flow, packet});
                }
            }
            if (sender.probe(now))
                receivers[flow].probe(now);
            cc.feedback(sender.events(), now);
        }
        for (auto it = network.begin(); it != network.end();) {
            if (it->at > now) {
                ++it;
                continue;
            }
            receivers[it->flow].accept(it->packet, now);
            it = network.erase(it);
        }
        for (unsigned flow = 0; flow < 2; ++flow) {
            auto& receiver = receivers[flow];
            auto consumed = receiver.consumed();
            while (auto bytes = receiver.peek(consumed))
                consumed += bytes->size();
            receiver.consume(consumed, now);
            if (receiver.ack_due(now))
                feedback.push_back({now + 20000, flow, receiver.ack(now)});
        }
        for (auto it = feedback.begin(); it != feedback.end();) {
            if (it->at > now) {
                ++it;
                continue;
            }
            check(senders[it->flow].acknowledge(it->ack, now), "competing ACK");
            it = feedback.erase(it);
        }
        for (unsigned flow = 0; flow < 2; ++flow)
            controllers[flow].feedback(senders[flow].events(), now);
        if (!measured && (senders[0].complete() || senders[1].complete())) {
            double a = double(senders[0].delivered()), b = double(senders[1].delivered());
            fairness = (a + b) * (a + b) / (2 * (a * a + b * b));
            measured = true;
            check(std::min(a, b) > total * .1, "competing sender starvation");
        }
        if (senders[0].complete() && senders[1].complete()) {
            std::cout << "PASS two competing flows Jain-at-first-finish=" << fairness
                      << " completion=" << double(now) / 1e6 << "s\n";
            return;
        }
    }
    check(false, "competing flows completion");
}
int main() {
    try {
        sampler_tests();
        state_tests();
        link_test("controller-stable", false, false);
        link_test("controller-capacity-rtt", true, false);
        link_test("controller-ack-compression", true, true);
        competing_flows();
        std::cout << "All congestion-controller tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
