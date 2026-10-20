#pragma once
#include "file_io.hpp"
#include "congestion.hpp"
#include "session_io.hpp"
#include <arpa/inet.h>
#include <netdb.h>
#include <iostream>

namespace ufcp {
enum class RemoteMode : uint8_t { Auto, Udp, Ssh };
struct TransferOptions {
    size_t window = 32, receive_chunks = 64;
    unsigned delay_ms = 0;
    Time pace = 1000;
    bool bbr = true;
};
struct RemoteOptions : TransferOptions {
    RemoteMode mode = RemoteMode::Auto;
    std::string ssh_program = "ssh", remote_program = "ufcp", ssh_config, udp_address;
};
inline std::string endpoint(const sockaddr_in& peer) {
    char text[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &peer.sin_addr, text, sizeof(text));
    return std::string(text) + ":" + std::to_string(ntohs(peer.sin_port));
}
inline int udp_socket() {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    sockaddr_in local{};
    local.sin_family = AF_INET;
    if (bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}
inline uint16_t udp_port(int fd) {
    sockaddr_in local{};
    socklen_t size = sizeof(local);
    require(getsockname(fd, reinterpret_cast<sockaddr*>(&local), &size) == 0,
            "cannot inspect UDP endpoint");
    return ntohs(local.sin_port);
}
inline bool same_peer(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}
inline bool raw_receive(int fd, Bytes& bytes, sockaddr_in& peer) {
    if (fd < 0)
        return false;
    bytes.resize(PacketCipher::MAX_SEALED + 1);
    socklen_t length = sizeof(peer);
    auto n =
        recvfrom(fd, bytes.data(), bytes.size(), 0, reinterpret_cast<sockaddr*>(&peer), &length);
    if (n < 0 &&
        (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNREFUSED))
        return false;
    require(n >= 0, "UDP receive failed");
    bytes.resize(size_t(n));
    return true;
}
inline bool raw_send(int fd, const sockaddr_in& peer, const Bytes& bytes, bool probing = false) {
    auto n = sendto(fd, bytes.data(), bytes.size(), 0, reinterpret_cast<const sockaddr*>(&peer),
                    sizeof(peer));
    if (n < 0 && probing)
        return false;
    if (n < 0 &&
        (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ECONNREFUSED))
        return false;
    require(n == ssize_t(bytes.size()), errno == EMSGSIZE
                                            ? "path MTU too small for encrypted UDP datagram"
                                            : "UDP send failed");
    return true;
}
inline bool resolve_udp(const std::string& host, uint16_t port, sockaddr_in& peer) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* addresses = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &addresses) != 0)
        return false;
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> cleanup(addresses, freeaddrinfo);
    if (!addresses)
        return false;
    peer = *reinterpret_cast<sockaddr_in*>(addresses->ai_addr);
    peer.sin_port = htons(port);
    return true;
}
inline Bytes encrypted_record(PacketCipher& cipher, uint8_t kind, const Bytes& bytes) {
    Bytes plain(1 + bytes.size());
    plain[0] = kind;
    std::copy(bytes.begin(), bytes.end(), plain.begin() + 1);
    return cipher.seal(plain);
}
inline void send_data_record(FrameChannel& channel, int udp, const sockaddr_in& peer,
                             PacketCipher& cipher, bool direct, const Bytes& bytes) {
    if (direct)
        raw_send(udp, peer, encrypted_record(cipher, 2, bytes));
    else
        channel.send(Control::Packet, bytes);
}
inline bool receive_data_record(int udp, const sockaddr_in& peer, PacketCipher& cipher,
                                Bytes& packet) {
    Bytes sealed, plain;
    sockaddr_in from{};
    if (!raw_receive(udp, sealed, from) || !same_peer(peer, from) || !cipher.open(sealed, plain) ||
        plain[0] != 2)
        return false;
    packet.assign(plain.begin() + 1, plain.end());
    return valid(packet);
}
inline Bytes completion(uint64_t total, const Bytes& hash) {
    require(hash.size() == 32, "invalid final digest");
    Bytes bytes(40);
    put(bytes, 0, total, 8);
    std::copy(hash.begin(), hash.end(), bytes.begin() + 8);
    return bytes;
}
// Requirement: the SSH helper receives remote paths as framed data and never inserts them into shell commands.
inline void remote_helper(FrameChannel& channel) {
    diagnostic("helper waiting for INIT");
    auto init = channel.expect(Control::Init, 30000000).bytes;
    require(init.size() >= 94 && get(init, 0, 4) == 0x55465331 && init[20] <= 2,
            "incompatible SSH session setup");
    uint64_t total = get(init, 4, 8), session = get(init, 12, 8);
    size_t window = size_t(get(init, 21, 2)), capacity = size_t(get(init, 23, 2));
    unsigned delay = unsigned(get(init, 25, 2));
    size_t path_length = size_t(get(init, 91, 2));
    require(window && window <= MAX_CHUNKS && capacity && capacity <= MAX_CHUNKS && delay <= 1000 &&
                path_length && path_length <= 4096 && init.size() == 93 + path_length,
            "invalid SSH session limits");
    std::string destination(init.begin() + 93, init.end());
    require(destination.find('\0') == std::string::npos, "remote path contains NUL");
    PacketCipher incoming(Bytes(init.begin() + 27, init.begin() + 59)),
        outgoing(Bytes(init.begin() + 59, init.begin() + 91));
    OPENSSL_cleanse(init.data() + 27, 64);
    diagnostic("helper INIT validated bytes=" + std::to_string(total) +
               " window=" + std::to_string(window) + " receive-chunks=" + std::to_string(capacity));
    OutputFile file(destination);
    FileWriter writer(file.fd(), delay);
    Receiver receiver(total, capacity);
    ScopedFd udp(init[20] == uint8_t(RemoteMode::Ssh) ? -1 : udp_socket());
    Bytes ready(10);
    put(ready, 0, receiver.limit(), 8);
    put(ready, 8, udp.fd >= 0 ? udp_port(udp.fd) : 0, 2);
    diagnostic("helper READY UDP port=" + std::to_string(get(ready, 8, 2)));
    channel.send(Control::Ready, ready);
    bool selected = false, direct = false, peer_known = false, closed = false, published = false;
    sockaddr_in peer{};
    uint64_t scheduled = 0;
    Bytes finish;
    Time deadline = session_now() + 15000000;
    while (session_now() < deadline) {
        auto now = session_now();
        channel.flush();
        // Receipt ACKs track buffered data; receiver credit advances only after ordered disk writes.
        uint64_t written = writer.written();
        receiver.consume(written, now);
        while (const Bytes* bytes = receiver.peek(scheduled)) {
            if (!writer.push(*bytes))
                break;
            scheduled += bytes->size();
        }
        if (scheduled == total && !closed) {
            writer.close();
            closed = true;
        }
        if (!published && written < scheduled)
            deadline = now + 15000000;
        if (selected && !published && receiver.ack_due(now) &&
            (direct || channel.room(MAX_DATAGRAM)))
            send_data_record(channel, udp.fd, peer, outgoing, direct,
                             ack_packet(session, receiver.ack(now)));
        for (unsigned count = 0; count < 16; ++count) {
            Frame frame;
            if (!channel.next(frame))
                break;
            now = session_now();
            if (frame.type == Control::Select && !selected && frame.bytes.size() == 1 &&
                frame.bytes[0] >= 1 && frame.bytes[0] <= 2) {
                direct = frame.bytes[0] == uint8_t(RemoteMode::Udp);
                require(!direct || (udp.fd >= 0 && peer_known),
                        "UDP reachability was not authenticated");
                if (!direct && udp.fd >= 0) {
                    close(udp.fd);
                    udp.fd = -1;
                }
                diagnostic(direct ? "helper selected direct UDP" : "helper selected SSH/TCP");
                selected = true;
                channel.send(Control::Selected, frame.bytes);
            } else if (frame.type == Control::Packet && selected && !direct && !published) {
                Transmission packet;
                require(decode_data(frame.bytes, packet) && get(frame.bytes, 8, 8) == session &&
                            receiver.accept(packet, now),
                        "invalid tunneled DATA");
            } else if (frame.type == Control::Finish && selected && !published && finish.empty()) {
                require(frame.bytes.size() == 40 && get(frame.bytes, 0, 8) == total,
                        "invalid finish request");
                finish = std::move(frame.bytes);
            } else if (frame.type == Control::Close && frame.bytes.empty() && published)
                return;
            else
                throw std::runtime_error("unexpected SSH session message");
            if (!published)
                deadline = now + 15000000;
        }
        Bytes sealed, plain;
        sockaddr_in from{};
        bool received = !published && raw_receive(udp.fd, sealed, from);
        bool authenticated = received && incoming.open(sealed, plain);
        if (received && !selected)
            diagnostic("helper UDP probe received from=" + endpoint(from) +
                       " bytes=" + std::to_string(sealed.size()) +
                       " authenticated=" + std::to_string(authenticated));
        if (authenticated) {
            now = session_now();
            if (plain[0] == 1 && plain.size() == PacketCipher::MAX_PLAIN && !selected) {
                peer = from;
                peer_known = true;
                bool replied = raw_send(udp.fd, peer, outgoing.seal(plain), true);
                diagnostic("helper probe reply sent=" + std::to_string(replied) +
                           " peer=" + endpoint(peer));
                deadline = now + 15000000;
            } else if (selected && direct && same_peer(peer, from) && plain[0] == 2) {
                Bytes bytes(plain.begin() + 1, plain.end());
                Transmission packet;
                if (valid(bytes) && get(bytes, 8, 8) == session) {
                    if (decode_data(bytes, packet) && receiver.accept(packet, now))
                        deadline = now + 15000000;
                    else if (bytes[4] == PROBE && bytes.size() == HEADER && !get(bytes, 16, 8)) {
                        receiver.probe(now);
                        deadline = now + 15000000;
                    }
                }
            }
        }
        if (!published && !finish.empty() && receiver.complete() && writer.done()) {
            require(finish == completion(total, writer.hash()),
                    "remote SHA-256 verification failed");
            // Requirement: final success is authenticated over SSH only after verified no-overwrite publication.
            file.publish();
            published = true;
            if (udp.fd >= 0) {
                close(udp.fd);
                udp.fd = -1;
            }
            channel.send(Control::Complete, finish);
            deadline = session_now() + 5000000;
        }
        channel.wait(1000, udp.fd);
    }
    throw std::runtime_error(published ? "completion was published but SSH close was not confirmed"
                                       : "remote receiver idle timeout");
}

// Requirement: select direct authenticated UDP when available and explicitly use SSH/TCP otherwise.
inline void remote_copy(const std::string& source, const std::string& target,
                        const RemoteOptions& options) {
    diagnostic("role=sender startup mode=" + std::to_string(unsigned(options.mode)) +
               " window=" + std::to_string(options.window) +
               " receive-chunks=" + std::to_string(options.receive_chunks));
    size_t colon = target.find(':');
    require(colon != std::string::npos && colon && colon + 1 < target.size(),
            "remote target must be [user@]host:path");
    std::string host = target.substr(0, colon), destination = target.substr(colon + 1);
    require(destination.size() <= 4096 && destination.find('\0') == std::string::npos,
            "invalid remote destination path");
    ScopedFd input(open(source.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
    struct stat original {};
    require(input.fd >= 0 && fstat(input.fd, &original) == 0 && S_ISREG(original.st_mode) &&
                original.st_size >= 0,
            "source must be a regular file");
    uint64_t total = uint64_t(original.st_size), session = get(random_bytes(8), 0, 8);
    Bytes keys = random_bytes(64);
    PacketCipher outgoing(Bytes(keys.begin(), keys.begin() + 32)),
        incoming(Bytes(keys.begin() + 32, keys.end()));
    diagnostic("sender source bytes=" + std::to_string(total));
    SshProcess ssh(host, options.ssh_program, options.remote_program, options.ssh_config);
    FrameChannel channel(ssh.fd(), ssh.fd());
    Bytes init(93 + destination.size());
    put(init, 0, 0x55465331, 4);
    put(init, 4, total, 8);
    put(init, 12, session, 8);
    init[20] = uint8_t(options.mode);
    put(init, 21, options.window, 2);
    put(init, 23, options.receive_chunks, 2);
    put(init, 25, options.delay_ms, 2);
    std::copy(keys.begin(), keys.end(), init.begin() + 27);
    put(init, 91, destination.size(), 2);
    std::copy(destination.begin(), destination.end(), init.begin() + 93);
    diagnostic("sender sending INIT; waiting for remote helper READY");
    channel.send(Control::Init, init);
    OPENSSL_cleanse(keys.data(), keys.size());
    OPENSSL_cleanse(init.data() + 27, 64);
    auto ready = channel.expect(Control::Ready, 30000000).bytes;
    require(ready.size() == 10 && get(ready, 0, 8) <= total, "invalid remote ready response");
    diagnostic("sender READY received remote UDP port=" + std::to_string(get(ready, 8, 2)));
    ScopedFd udp(options.mode == RemoteMode::Ssh ? -1 : udp_socket());
    diagnostic("sender local UDP port=" + std::to_string(udp.fd >= 0 ? udp_port(udp.fd) : 0));
    sockaddr_in peer{};
    bool direct = false;
    if (options.mode != RemoteMode::Ssh && udp.fd >= 0 && get(ready, 8, 2)) {
        std::string hostname =
            options.udp_address.empty()
                ? host.substr(host.find('@') == std::string::npos ? 0 : host.find('@') + 1)
                : options.udp_address;
        bool resolved = resolve_udp(hostname, uint16_t(get(ready, 8, 2)), peer);
        diagnostic("sender resolve host=" + hostname + " success=" + std::to_string(resolved));
        if (resolved) {
            diagnostic("sender probing remote UDP endpoint=" + endpoint(peer));
            // Requirement: bidirectional probes test full-sized encrypted datagrams before choosing native UDP.
            Bytes challenge(PacketCipher::MAX_PLAIN - 1);
            auto nonce = random_bytes(16);
            std::copy(nonce.begin(), nonce.end(), challenge.begin());
            Time until = session_now() + 1200000, next = 0;
            while (session_now() < until && !direct) {
                auto now = session_now();
                if (now >= next) {
                    bool sent = raw_send(udp.fd, peer, encrypted_record(outgoing, 1, challenge), true);
                    diagnostic("sender UDP probe sent=" + std::to_string(sent));
                    next = now + 200000;
                }
                Bytes sealed, plain;
                sockaddr_in from{};
                if (raw_receive(udp.fd, sealed, from)) {
                    bool expected_peer = same_peer(peer, from);
                    bool authenticated = expected_peer && incoming.open(sealed, plain);
                    direct = authenticated && plain.size() == PacketCipher::MAX_PLAIN &&
                             plain[0] == 1 && Bytes(plain.begin() + 1, plain.end()) == challenge;
                    diagnostic("sender UDP probe reply from=" + endpoint(from) +
                               " bytes=" + std::to_string(sealed.size()) +
                               " expected-peer=" + std::to_string(expected_peer) +
                               " authenticated=" + std::to_string(authenticated) +
                               " challenge-matched=" + std::to_string(direct));
                }
                Frame unexpected;
                require(!channel.next(unexpected), "unexpected control message during UDP probe");
                if (!direct)
                    channel.wait(1000, udp.fd);
            }
        }
    }
    diagnostic("sender UDP negotiation complete reachable=" + std::to_string(direct));
    require(direct || options.mode != RemoteMode::Udp,
            "authenticated UDP path unavailable; strict UDP mode forbids SSH/TCP fallback");
    // Agree on one transport before payload starts; a later UDP failure does not switch modes.
    channel.send(Control::Select, Bytes{uint8_t(direct ? RemoteMode::Udp : RemoteMode::Ssh)});
    auto selected = channel.expect(Control::Selected).bytes;
    require(selected == Bytes{uint8_t(direct ? RemoteMode::Udp : RemoteMode::Ssh)},
            "remote transport selection mismatch");
    if (!direct && udp.fd >= 0) {
        close(udp.fd);
        udp.fd = -1;
    }
    std::cout << (direct ? "Transport: direct UDP (authenticated encryption)\n"
                  : options.mode == RemoteMode::Ssh
                      ? "Transport: SSH/TCP (requested); userspace congestion control disabled\n"
                      : "Transport: SSH/TCP (fallback: authenticated UDP probe unavailable); "
                        "userspace congestion control disabled\n")
              << std::flush;
    Sender sender(total, get(ready, 0, 8), options.window, session_now());
    sender.reliable_link(!direct);
    sender.budget({options.window * PAYLOAD, direct ? options.pace : 0});
    CongestionController controller(options.window, session_now());
    FileReader reader(input.fd, original, options.delay_ms);
    while (!sender.complete() || !reader.done()) {
        channel.flush();
        Bytes bytes;
        while (sender.can_queue() && reader.pop(bytes))
            sender.queue(std::move(bytes));
        auto now = session_now();
        if (direct && options.bbr) {
            controller.tick(now, sender.pending_size() != 0,
                            !sender.data_available(now) &&
                                sender.flight_bytes() < controller.window());
            sender.budget(controller.budget());
        }
        Transmission packet;
        if ((direct || channel.room(MAX_DATAGRAM)) && sender.next(now, packet))
            send_data_record(channel, udp.fd, peer, outgoing, direct, data_packet(session, packet));
        else
            sender.tick(now);
        if (sender.probe(now))
            send_data_record(channel, udp.fd, peer, outgoing, direct,
                             ufcp::packet(PROBE, session, 0));
        auto events = sender.events();
        if (direct && options.bbr)
            controller.feedback(events, now);
        for (unsigned count = 0; count < 16; ++count) {
            Frame frame;
            if (!channel.next(frame))
                break;
            require(!direct && frame.type == Control::Packet,
                    "unexpected SSH message during transfer");
            Ack ack;
            require(decode_ack(frame.bytes, ack) && get(frame.bytes, 8, 8) == session &&
                        sender.acknowledge(ack, session_now()),
                    "invalid tunneled ACK");
        }
        if (direct && receive_data_record(udp.fd, peer, incoming, bytes) &&
            get(bytes, 8, 8) == session) {
            Ack ack;
            if (decode_ack(bytes, ack))
                sender.acknowledge(ack, session_now());
        }
        events = sender.events();
        if (direct && options.bbr)
            controller.feedback(events, session_now());
        channel.wait(direct ? sender.wait(session_now()) : 1000, direct ? udp.fd : -1);
    }
    struct stat current {};
    require(fstat(input.fd, &current) == 0 && same_source(original, current),
            "source changed during transfer");
    // DATA ACKs prove delivery; authenticated COMPLETE separately proves verification and publication.
    Bytes finish = completion(total, reader.hash());
    bool confirmed = false;
    try {
        channel.send(Control::Finish, finish);
        Time deadline = session_now() + 15000000;
        while (!confirmed && session_now() < deadline) {
            channel.flush();
            Frame result;
            if (channel.next(result)) {
                if (!direct && result.type == Control::Packet) {
                    Ack ack;
                    require(decode_ack(result.bytes, ack) && get(result.bytes, 8, 8) == session,
                            "invalid trailing tunneled ACK");
                } else {
                    require(result.type == Control::Complete && result.bytes == finish,
                            "remote completion digest mismatch");
                    confirmed = true;
                }
            } else
                channel.wait();
        }
        require(confirmed, "SSH completion timeout");
        channel.send(Control::Close);
        channel.finish_writes();
        ssh.success();
    } catch (const std::exception& error) {
        throw std::runtime_error(
            std::string(confirmed ? "destination confirmed but SSH shutdown failed: "
                                  : "completion unconfirmed: destination may exist: ") +
            error.what());
    }
    std::cout << "Complete: " << sender.delivered()
              << " bytes verified with SHA-256 and finalized\n";
    if (direct && options.bbr)
        std::cout << "Controller: bbr-inspired\n";
}
inline int helper_main() {
    FrameChannel channel(STDIN_FILENO, STDOUT_FILENO);
    try {
        remote_helper(channel);
        return 0;
    } catch (const std::exception& error) {
        try {
            std::string message(error.what());
            if (message.size() > 1024)
                message.resize(1024);
            channel.send(Control::Error, Bytes(message.begin(), message.end()));
            channel.finish_writes(200000);
        } catch (...) {
        }
        diagnostic("helper failed: " + std::string(error.what()));
        std::cerr << "ufcp helper: " << error.what() << '\n';
        return 1;
    }
}
} // namespace ufcp
