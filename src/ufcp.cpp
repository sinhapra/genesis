// Requirement: keep socket/session orchestration separate from wire, transport, and file adapters.
#include "file_io.hpp"
#include "congestion.hpp"
#include "remote.hpp"
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <cstring>
#include <iostream>
#include <memory>
#include <random>
#include <string>

using namespace ufcp;
uint64_t number(const std::string& text, uint64_t maximum) {
    require(!text.empty() && text.find_first_not_of("0123456789") == std::string::npos,
            "invalid numeric option");
    auto value = std::stoull(text);
    require(value <= maximum, "option out of range");
    return value;
}

sockaddr_in address(const char* ip, const char* port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    auto value = number(port, 65535);
    require(value > 0, "invalid port");
    a.sin_port = htons(uint16_t(value));
    require(inet_pton(AF_INET, ip, &a.sin_addr) == 1, "use a numeric IPv4 address");
    return a;
}

void send_packet(int fd, const sockaddr_in& peer, const Bytes& bytes) {
    ssize_t n;
    do {
        n = sendto(fd, bytes.data(), bytes.size(), 0, reinterpret_cast<const sockaddr*>(&peer),
                   sizeof(peer));
    } while (n < 0 && errno == EINTR);
    if (n < 0 && errno == EMSGSIZE)
        throw std::runtime_error("path MTU too small for configured datagram");
    require(n == ssize_t(bytes.size()), "UDP send failed");
}

bool receive(int fd, Bytes& bytes, sockaddr_in& peer, Time timeout) {
    timespec duration{time_t(timeout / 1000000), long((timeout % 1000000) * 1000)};
    pollfd p{fd, POLLIN, 0};
    int r = ppoll(&p, 1, &duration, nullptr);
    if (r < 0 && errno == EINTR)
        return false;
    require(r >= 0, "poll failed");
    if (!r)
        return false;
    require(!(p.revents & (POLLERR | POLLHUP | POLLNVAL)), "UDP socket error");
    bytes.resize(MAX_DATAGRAM + 1);
    socklen_t length = sizeof(peer);
    auto n =
        recvfrom(fd, bytes.data(), bytes.size(), 0, reinterpret_cast<sockaddr*>(&peer), &length);
    if (n < 0 && errno == EINTR)
        return false;
    require(n >= 0, "UDP receive failed");
    bytes.resize(size_t(n));
    return valid(bytes);
}

Bytes exchange(int fd, const sockaddr_in& peer, const Bytes& request, uint64_t total) {
    for (int attempt = 0; attempt < 20; ++attempt) {
        send_packet(fd, peer, request);
        auto deadline = session_now() + 200000;
        while (session_now() < deadline) {
            Bytes reply;
            sockaddr_in from{};
            Time wait = std::max<Time>(1, deadline - session_now());
            if (!receive(fd, reply, from, wait) || !same_peer(from, peer) || reply[4] != ACK ||
                get(reply, 8, 8) != get(request, 8, 8) || get(reply, 16, 8) != get(request, 16, 8))
                continue;
            if (request[4] == START && reply.size() == HEADER + 9 && reply[HEADER] == START &&
                get(reply, HEADER + 1, 8) <= total)
                return reply;
            if (request[4] == FINISH && reply.size() == HEADER + 1 && reply[HEADER] == FINISH)
                return reply;
        }
    }
    throw std::runtime_error(request[4] == FINISH ? "completion unconfirmed: destination may exist"
                                                  : "UDP acknowledgement timeout");
}

void sender(const char* ip, const char* port, const char* path, const TransferOptions& config) {
    ScopedFd input(open(path, O_RDONLY | O_NONBLOCK));
    struct stat original {};
    require(fstat(input.fd, &original) == 0 && S_ISREG(original.st_mode) && original.st_size >= 0,
            "source must be a regular file");
    uint64_t total = uint64_t(original.st_size);
    ScopedFd socket_fd(socket(AF_INET, SOCK_DGRAM, 0));
    require(socket_fd.fd >= 0, "cannot create UDP socket");
    auto peer = address(ip, port);
    std::random_device random;
    uint64_t session = (uint64_t(random()) << 32) ^ random();
    Bytes metadata(8);
    put(metadata, 0, total, 8);
    auto reply = exchange(socket_fd.fd, peer, packet(START, session, 0, metadata), total);
    Sender transport(total, get(reply, HEADER + 1, 8), config.window, session_now());
    CongestionController controller(config.window, session_now());
    transport.budget({config.window * PAYLOAD, config.pace});
    FileReader reader(input.fd, original, config.delay_ms);
    while (!transport.complete() || !reader.done()) {
        Bytes bytes;
        while (transport.can_queue() && reader.pop(bytes))
            transport.queue(std::move(bytes));
        auto now = session_now();
        Transmission outgoing;
        if (config.bbr) {
            bool limited =
                !transport.data_available(now) && transport.flight_bytes() < controller.window();
            controller.tick(now, transport.pending_size() != 0, limited);
            transport.budget(controller.budget());
        }
        if (transport.next(now, outgoing))
            send_packet(socket_fd.fd, peer, data_packet(session, outgoing));
        if (transport.probe(now))
            send_packet(socket_fd.fd, peer, packet(PROBE, session, 0));
        // Requirement: feed actual transmission, ACK, and loss events into the userspace controller.
        auto events = transport.events();
        if (config.bbr)
            controller.feedback(events, now);
        Bytes incoming;
        sockaddr_in from{};
        if (receive(socket_fd.fd, incoming, from, transport.wait(session_now())) &&
            same_peer(from, peer) && get(incoming, 8, 8) == session) {
            Ack ack;
            if (decode_ack(incoming, ack))
                transport.acknowledge(ack, session_now());
        }
        events = transport.events();
        if (config.bbr)
            controller.feedback(events, session_now());
    }
    struct stat current {};
    require(fstat(input.fd, &current) == 0 && same_source(original, current),
            "source changed during transfer");
    Bytes digest(4);
    put(digest, 0, reader.digest(), 4);
    exchange(socket_fd.fd, peer, packet(FINISH, session, total, digest), total);
    std::cout << "Complete: " << transport.delivered() << " bytes acknowledged and finalized\n";
    if (config.bbr)
        std::cout << "Controller: bbr-inspired mode=" << controller.mode_name()
                  << " bandwidth=" << uint64_t(controller.bandwidth())
                  << "B/s pacing=" << uint64_t(controller.pacing_rate())
                  << "B/s cwnd=" << controller.window() << " min-rtt=" << controller.min_rtt()
                  << "us lost=" << controller.losses() << "B\n";
}

void receiver(const char* ip, const char* port, const char* path, const TransferOptions& config) {
    auto local = address(ip, port);
    ScopedFd socket_fd(socket(AF_INET, SOCK_DGRAM, 0));
    require(socket_fd.fd >= 0, "cannot create UDP socket");
    require(bind(socket_fd.fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0,
            "UDP bind failed");
    OutputFile output(path);
    FileWriter writer(output.fd(), config.delay_ms);
    std::unique_ptr<Receiver> transport;
    sockaddr_in peer{};
    uint64_t session = 0, total = 0, scheduled = 0;
    bool complete = false, writer_closed = false;
    Time deadline = session_now() + 15000000;
    std::cout << "Listening on " << ip << ':' << port << std::endl;
    while (session_now() < deadline) {
        auto now = session_now();
        auto written = writer.written();
        if (transport && !complete) {
            // Requirement: only worker-confirmed ordered writes release receive capacity.
            transport->consume(written, now);
            while (const Bytes* bytes = transport->peek(scheduled)) {
                if (!writer.push(*bytes))
                    break;
                scheduled += bytes->size();
            }
            if (scheduled == total && !writer_closed) {
                writer.close();
                writer_closed = true;
            }
            if (written < scheduled)
                deadline = now + 15000000;
            if (transport->ack_due(now))
                send_packet(socket_fd.fd, peer, ack_packet(session, transport->ack(now)));
        }
        Bytes incoming;
        sockaddr_in from{};
        if (!receive(socket_fd.fd, incoming, from, 1000))
            continue;
        now = session_now();
        auto type = Type(incoming[4]);
        auto position = get(incoming, 16, 8);
        if (!transport) {
            if (type != START || position || incoming.size() != HEADER + 8)
                continue;
            total = get(incoming, HEADER, 8);
            peer = from;
            session = get(incoming, 8, 8);
            transport = std::make_unique<Receiver>(total, config.receive_chunks);
        }
        if (!same_peer(from, peer) || get(incoming, 8, 8) != session)
            continue;
        bool accepted = false;
        if (type == START && !position && incoming.size() == HEADER + 8 &&
            get(incoming, HEADER, 8) == total && !complete) {
            Bytes ack(9);
            ack[0] = START;
            put(ack, 1, transport->limit(), 8);
            send_packet(socket_fd.fd, peer, packet(ACK, session, 0, ack));
            accepted = true;
        } else if (type == DATA && !complete) {
            Transmission value;
            if (decode_data(incoming, value))
                accepted = transport->accept(value, now);
        } else if (type == PROBE && !position && incoming.size() == HEADER && !complete) {
            transport->probe(now);
            accepted = true;
        } else if (type == FINISH && position == total && incoming.size() == HEADER + 4 &&
                   transport->complete() && writer.done() &&
                   get(incoming, HEADER, 4) == writer.digest()) {
            if (!complete) {
                // Requirement: publish verified output without replacing an existing destination.
                output.publish();
                complete = true;
                deadline = now + 5000000;
                std::cout << "Finalized: " << total << " bytes\n";
            }
            send_packet(socket_fd.fd, peer, packet(ACK, session, total, Bytes{FINISH}));
            accepted = true;
        }
        if (accepted && !complete)
            deadline = now + 15000000;
    }
    require(complete, "receiver idle timeout; incomplete temporary file removed");
}

int main(int argc, char** argv) {
    try {
        signal(SIGPIPE, SIG_IGN);
        if (argc == 2 && std::string(argv[1]) == "--helper")
            return helper_main();
        bool copy = argc >= 2 && std::string(argv[1]) == "copy";
        int option_start = copy ? 4 : 5;
        require(argc >= option_start, copy ? "usage: ufcp copy SOURCE [user@]HOST:DEST [OPTIONS]"
                                           : "usage: ufcp send|recv IPv4 PORT FILE [OPTIONS]");
        RemoteOptions remote;
        TransferOptions& config = remote;
        bool pace_set = false;
        for (int i = option_start; i < argc; ++i) {
            std::string option(argv[i]);
            auto equal = option.find('=');
            require(equal != std::string::npos, "options require =VALUE");
            auto key = option.substr(0, equal), value = option.substr(equal + 1);
            if (key == "--cc") {
                require(value == "bbr-inspired" || value == "fixed",
                        "cc must be bbr-inspired or fixed");
                config.bbr = value == "bbr-inspired";
            } else if (key == "--window") {
                config.window = size_t(number(value, MAX_CHUNKS));
                require(config.window > 0, "window must be positive");
            } else if (key == "--receive-chunks") {
                config.receive_chunks = size_t(number(value, MAX_CHUNKS));
                require(config.receive_chunks > 0, "receive capacity must be positive");
            } else if (key == "--pace-us") {
                config.pace = Time(number(value, 1000000));
                require(config.pace > 0, "pacing must be positive");
                pace_set = true;
            } else if (key == "--io-delay-ms")
                config.delay_ms = unsigned(number(value, 1000));
            else if (copy && key == "--transport") {
                require(value == "auto" || value == "udp" || value == "ssh",
                        "transport must be auto, udp, or ssh");
                remote.mode = value == "auto"  ? RemoteMode::Auto
                              : value == "udp" ? RemoteMode::Udp
                                               : RemoteMode::Ssh;
            } else if (copy && key == "--remote-program")
                remote.remote_program = value;
            else if (copy && key == "--ssh-config")
                remote.ssh_config = value;
            else if (copy && key == "--ssh-program")
                remote.ssh_program = value;
            else if (copy && key == "--udp-address")
                remote.udp_address = value;
            else
                throw std::runtime_error("unknown option");
        }
        require(!config.bbr || !pace_set, "--pace-us requires --cc=fixed");
        if (copy) {
            remote_copy(argv[2], argv[3], remote);
            return 0;
        }
        std::string mode(argv[1]);
        if (mode == "send")
            sender(argv[2], argv[3], argv[4], config);
        else if (mode == "recv")
            receiver(argv[2], argv[3], argv[4], config);
        else
            throw std::runtime_error("mode must be send or recv");
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "ufcp: " << e.what() << '\n';
        return 1;
    }
}
