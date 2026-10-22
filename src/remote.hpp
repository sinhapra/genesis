#pragma once
#include "file_io.hpp"
#include "congestion.hpp"
#include "session_io.hpp"
#include <arpa/inet.h>
#include <netdb.h>
#include <cstdio>
#include <iostream>

namespace ufcp {
enum class RemoteMode : uint8_t { Auto, Udp, Ssh };
struct TransferOptions {
    size_t window = 4096, receive_chunks = 4096;
    unsigned delay_ms = 0;
    Time pace = 1000;
    bool bbr = true;
};
struct RemoteOptions : TransferOptions {
    RemoteMode mode = RemoteMode::Auto;
    bool stats = false;
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
inline bool sender_address(sockaddr_in& peer) {
    const char* connection = getenv("SSH_CONNECTION");
    if (!connection)
        return false;
    std::string client(connection);
    client = client.substr(0, client.find(' '));
    peer = {};
    peer.sin_family = AF_INET;
    return inet_pton(AF_INET, client.c_str(), &peer.sin_addr) == 1;
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
// Requirement: --stats exposes live transfer state (rate, model, RTT, window, loss) once per second.
class TransferStats {
    uint64_t total_, last_delivered_ = 0;
    Time started_, next_;
    bool direct_;

  public:
    TransferStats(uint64_t total, bool direct, Time now)
        : total_(total), started_(now), next_(now + 1000000), direct_(direct) {}
    void report(const Sender& sender, const CongestionController& controller, Time now) {
        if (now < next_)
            return;
        double seconds = double(now - started_) / 1e6;
        double interval = double(now - next_ + 1000000) / 1e6;
        uint64_t delivered = sender.delivered();
        std::fprintf(stderr, "stats t=%.1fs %.1f/%.1fMB %.0f%% rate=%.1fMbit/s inflight=%lluKB",
                     seconds, delivered / 1e6, total_ / 1e6,
                     total_ ? 100.0 * double(delivered) / double(total_) : 100.0,
                     double(delivered - last_delivered_) * 8 / 1e6 / interval,
                     (unsigned long long)(sender.flight_bytes() / 1024));
        if (direct_)
            std::fprintf(stderr,
                         " mode=%s bw=%.1fMbit/s pacing=%.1fMbit/s cwnd=%lluKB min-rtt=%.1fms "
                         "rto=%.1fms lost=%lluKB(%.2f%%)",
                         controller.mode_name(), controller.bandwidth() * 8 / 1e6,
                         controller.pacing_rate() * 8 / 1e6,
                         (unsigned long long)(controller.window() / 1024),
                         controller.min_rtt() / 1e3, sender.rto() / 1e3,
                         (unsigned long long)(controller.losses() / 1024),
                         sender.sent_bytes() ? 100.0 * double(controller.losses()) /
                                                   double(sender.sent_bytes())
                                             : 0.0);
        std::fprintf(stderr, "\n");
        last_delivered_ = delivered;
        next_ = now + 1000000;
    }
    void summary(const Sender& sender, const CongestionController& controller, Time now) const {
        double seconds = std::max(1e-6, double(now - started_) / 1e6);
        std::fprintf(stderr,
                     "Stats: %.1fMB in %.1fs average=%.1fMbit/s sent=%.1fMB retransmitted=%.2f%%",
                     sender.delivered() / 1e6, seconds, sender.delivered() * 8 / 1e6 / seconds,
                     sender.sent_bytes() / 1e6,
                     sender.sent_bytes()
                         ? 100.0 * double(sender.sent_bytes() - sender.delivered()) /
                               double(sender.sent_bytes())
                         : 0.0);
        if (direct_)
            std::fprintf(stderr, " min-rtt=%.1fms lost=%lluKB", controller.min_rtt() / 1e3,
                         (unsigned long long)(controller.losses() / 1024));
        std::fprintf(stderr, "\n");
    }
};
inline Bytes completion(uint64_t total, const Bytes& hash) {
    require(hash.size() == 32, "invalid final digest");
    Bytes bytes(40);
    put(bytes, 0, total, 8);
    std::copy(hash.begin(), hash.end(), bytes.begin() + 8);
    return bytes;
}
// The selected data path between the two ends; both transfer directions use it unchanged.
struct DataPath {
    FrameChannel& channel;
    int udp;
    sockaddr_in peer;
    PacketCipher& outgoing;
    PacketCipher& incoming;
    bool direct;
    uint64_t session;
    void send(const Bytes& packet) {
        send_data_record(channel, udp, peer, outgoing, direct, packet);
    }
};
// Requirement: the data sender owns pacing, congestion control and retransmission. It is the local
// command for uploads and the remote helper for downloads. Returns the FINISH digest.
inline Bytes transmit(DataPath& path, int fd, const struct stat& original, uint64_t limit,
                      const TransferOptions& options, bool show_stats) {
    uint64_t total = uint64_t(original.st_size);
    bool adaptive = path.direct && options.bbr;
    Sender sender(total, limit, options.window, session_now());
    sender.reliable_link(!path.direct);
    sender.budget({options.window * PAYLOAD, path.direct ? options.pace : 0});
    CongestionController controller(options.window, session_now());
    FileReader reader(fd, original, options.delay_ms);
    TransferStats stats(total, path.direct, session_now());
    while (!sender.complete() || !reader.done()) {
        path.channel.flush();
        if (show_stats)
            stats.report(sender, controller, session_now());
        Bytes bytes;
        while (sender.can_queue() && reader.pop(bytes))
            sender.queue(std::move(bytes));
        auto now = session_now();
        if (adaptive) {
            controller.tick(now, sender.pending_size() != 0,
                            !sender.data_available(now) &&
                                sender.flight_bytes() < controller.window());
            sender.budget(controller.budget());
        }
        // Send every packet the pacing schedule allows now (bounded), not one per loop pass.
        Transmission packet;
        unsigned burst = 0;
        while (burst < 16 && (path.direct || path.channel.room(MAX_DATAGRAM)) &&
               sender.next(now, packet)) {
            path.send(data_packet(path.session, packet));
            ++burst;
        }
        if (!burst)
            sender.tick(now);
        if (sender.probe(now))
            path.send(ufcp::packet(PROBE, path.session, 0));
        auto events = sender.events();
        if (adaptive)
            controller.feedback(events, now);
        // Error frames throw inside next(); direct UDP expects no other SSH traffic during transfer.
        for (unsigned count = 0; count < 16; ++count) {
            Frame frame;
            if (!path.channel.next(frame))
                break;
            require(!path.direct && frame.type == Control::Packet,
                    "unexpected SSH message during transfer");
            Ack ack;
            require(decode_ack(frame.bytes, ack) && get(frame.bytes, 8, 8) == path.session &&
                        sender.acknowledge(ack, session_now()),
                    "invalid tunneled ACK");
        }
        for (unsigned count = 0; path.direct && count < 64; ++count) {
            if (!receive_data_record(path.udp, path.peer, path.incoming, bytes))
                break;
            Ack ack;
            if (get(bytes, 8, 8) == path.session && decode_ack(bytes, ack))
                sender.acknowledge(ack, session_now());
        }
        events = sender.events();
        if (adaptive)
            controller.feedback(events, session_now());
        path.channel.wait(path.direct ? sender.wait(session_now()) : 1000,
                          path.direct ? path.udp : -1);
    }
    struct stat current {};
    require(fstat(fd, &current) == 0 && same_source(original, current),
            "source changed during transfer");
    if (show_stats)
        stats.summary(sender, controller, session_now());
    // DATA ACKs prove delivery; authenticated COMPLETE separately proves verification and publication.
    return completion(total, reader.hash());
}
// Sends FINISH and waits for the receiver's authenticated COMPLETE with the same size and digest.
inline void await_complete(DataPath& path, const Bytes& finish) {
    path.channel.send(Control::Finish, finish);
    Time deadline = session_now() + 15000000;
    while (session_now() < deadline) {
        path.channel.flush();
        Frame result;
        if (!path.channel.next(result)) {
            path.channel.wait();
            continue;
        }
        if (!path.direct && result.type == Control::Packet) {
            Ack ack;
            require(decode_ack(result.bytes, ack) && get(result.bytes, 8, 8) == path.session,
                    "invalid trailing tunneled ACK");
            continue;
        }
        require(result.type == Control::Complete && result.bytes == finish,
                "remote completion digest mismatch");
        return;
    }
    throw std::runtime_error("SSH completion timeout");
}
// Requirement: the data receiver ACKs, writes in order, verifies SHA-256, publishes atomically and
// confirms COMPLETE over SSH. It is the remote helper for uploads and the local command for downloads.
inline void receive_file(DataPath& path, OutputFile& file, uint64_t total, size_t capacity,
                         unsigned delay) {
    FileWriter writer(file.fd(), delay);
    Receiver receiver(total, capacity);
    bool closed = false;
    uint64_t scheduled = 0;
    Bytes finish;
    Time deadline = session_now() + 15000000;
    while (session_now() < deadline) {
        auto now = session_now();
        path.channel.flush();
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
        if (written < scheduled)
            deadline = now + 15000000;
        if (receiver.ack_due(now) && (path.direct || path.channel.room(MAX_DATAGRAM)))
            path.send(ack_packet(path.session, receiver.ack(now)));
        for (unsigned count = 0; count < 16; ++count) {
            Frame frame;
            if (!path.channel.next(frame))
                break;
            now = session_now();
            if (frame.type == Control::Packet && !path.direct) {
                Transmission packet;
                require(decode_data(frame.bytes, packet) &&
                            get(frame.bytes, 8, 8) == path.session && receiver.accept(packet, now),
                        "invalid tunneled DATA");
            } else if (frame.type == Control::Finish && finish.empty()) {
                require(frame.bytes.size() == 40 && get(frame.bytes, 0, 8) == total,
                        "invalid finish request");
                finish = std::move(frame.bytes);
            } else
                throw std::runtime_error("unexpected SSH session message type=" +
                                         std::to_string(unsigned(frame.type)));
            deadline = now + 15000000;
        }
        // Drain queued datagrams in one pass so a fast sender is not limited to one packet per poll.
        for (unsigned datagrams = 0; path.direct && datagrams < 64; ++datagrams) {
            Bytes sealed, plain;
            sockaddr_in from{};
            if (!raw_receive(path.udp, sealed, from))
                break;
            // Late probes and punches from setup are ignored; only authenticated DATA/PROBE count.
            if (!same_peer(path.peer, from) || !path.incoming.open(sealed, plain) || plain[0] != 2)
                continue;
            now = session_now();
            Bytes bytes(plain.begin() + 1, plain.end());
            Transmission packet;
            if (valid(bytes) && get(bytes, 8, 8) == path.session) {
                if (decode_data(bytes, packet) && receiver.accept(packet, now))
                    deadline = now + 15000000;
                else if (bytes[4] == PROBE && bytes.size() == HEADER && !get(bytes, 16, 8)) {
                    receiver.probe(now);
                    deadline = now + 15000000;
                }
            }
            if (receiver.ack_due(now))
                path.send(ack_packet(path.session, receiver.ack(now)));
        }
        if (!finish.empty() && receiver.complete() && writer.done()) {
            require(finish == completion(total, writer.hash()), "SHA-256 verification failed");
            // Requirement: final success is authenticated over SSH only after verified atomic publication.
            file.publish();
            path.channel.send(Control::Complete, finish);
            return;
        }
        path.channel.wait(1000, path.direct ? path.udp : -1);
    }
    throw std::runtime_error("receiver idle timeout");
}
// INIT flags (byte 95).
constexpr uint8_t INIT_DOWNLOAD = 1, INIT_STATS = 2;
// Requirement: the SSH helper receives remote paths as framed data and never inserts them into shell commands.
inline void remote_helper(FrameChannel& channel) {
    diagnostic("helper waiting for INIT");
    auto init = channel.expect(Control::Init, 30000000).bytes;
    require(init.size() >= 97 && get(init, 0, 4) == 0x55465333 && init[20] <= 2 &&
                !(init[95] & ~(INIT_DOWNLOAD | INIT_STATS)),
            "incompatible SSH session setup");
    uint64_t total = get(init, 4, 8), session = get(init, 12, 8);
    size_t window = size_t(get(init, 21, 2)), capacity = size_t(get(init, 23, 2));
    unsigned delay = unsigned(get(init, 25, 2));
    size_t path_length = size_t(get(init, 91, 2));
    require(window && window <= MAX_CHUNKS && capacity && capacity <= MAX_CHUNKS && delay <= 1000 &&
                path_length && path_length <= 4096 && init.size() == 96 + path_length,
            "invalid SSH session limits");
    uint16_t client_port = uint16_t(get(init, 93, 2));
    bool download = init[95] & INIT_DOWNLOAD, show_stats = init[95] & INIT_STATS;
    std::string remote_path(init.begin() + 96, init.end());
    require(remote_path.find('\0') == std::string::npos, "remote path contains NUL");
    PacketCipher incoming(Bytes(init.begin() + 27, init.begin() + 59)),
        outgoing(Bytes(init.begin() + 59, init.begin() + 91));
    OPENSSL_cleanse(init.data() + 27, 64);
    // Uploads write remote_path; downloads read it. Problems are reported before READY.
    std::unique_ptr<OutputFile> file;
    ScopedFd input;
    struct stat original {};
    if (download) {
        input.fd = open(remote_path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        require(input.fd >= 0 && fstat(input.fd, &original) == 0 && S_ISREG(original.st_mode) &&
                    original.st_size >= 0,
                "remote source must be a readable regular file");
        total = uint64_t(original.st_size);
    } else
        file = std::make_unique<OutputFile>(remote_path);
    uint64_t limit = std::min<uint64_t>(capacity * PAYLOAD, total);
    diagnostic(std::string("helper INIT validated direction=") +
               (download ? "download" : "upload") + " bytes=" + std::to_string(total) +
               " window=" + std::to_string(window) +
               " receive-chunks=" + std::to_string(capacity));
    ScopedFd udp(init[20] == uint8_t(RemoteMode::Ssh) ? -1 : udp_socket());
    // READY: upload = initial receive limit, download = source size; then the helper UDP port.
    Bytes ready(10);
    put(ready, 0, download ? total : limit, 8);
    put(ready, 8, udp.fd >= 0 ? udp_port(udp.fd) : 0, 2);
    diagnostic("helper READY UDP port=" + std::to_string(get(ready, 8, 2)));
    channel.send(Control::Ready, ready);
    // Requirement: open stateful firewalls/NATs on this side by sending first; the client's probes then arrive as replies.
    sockaddr_in punch{};
    bool punching = udp.fd >= 0 && client_port && sender_address(punch);
    punch.sin_port = htons(client_port);
    diagnostic(punching ? "helper punching toward client " + endpoint(punch)
                        : "helper not punching (no client UDP port or SSH_CONNECTION IPv4)");
    Time punch_at = 0, deadline = session_now() + 15000000;
    bool selected = false, direct = false, peer_known = false;
    sockaddr_in peer{};
    while (!selected) {
        require(session_now() < deadline, "helper timed out waiting for transport selection");
        auto now = session_now();
        channel.flush();
        Frame frame;
        if (channel.next(frame)) {
            require(frame.type == Control::Select && frame.bytes.size() == 1 &&
                        frame.bytes[0] >= 1 && frame.bytes[0] <= 2,
                    "invalid transport selection");
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
            break;
        }
        if (punching && now >= punch_at) {
            raw_send(udp.fd, punch, encrypted_record(outgoing, 3, {}), true);
            punch_at = now + 100000;
        }
        Bytes sealed, plain;
        sockaddr_in from{};
        if (raw_receive(udp.fd, sealed, from)) {
            bool authenticated = incoming.open(sealed, plain);
            diagnostic("helper UDP probe received from=" + endpoint(from) +
                       " bytes=" + std::to_string(sealed.size()) +
                       " authenticated=" + std::to_string(authenticated));
            if (authenticated && plain[0] == 1 && plain.size() == PacketCipher::MAX_PLAIN) {
                peer = from;
                peer_known = true;
                bool replied = raw_send(udp.fd, peer, outgoing.seal(plain), true);
                diagnostic("helper probe reply sent=" + std::to_string(replied) +
                           " peer=" + endpoint(peer));
            }
        }
        channel.wait(1000, udp.fd);
    }
    DataPath path{channel, udp.fd, peer, outgoing, incoming, direct, session};
    if (download) {
        TransferOptions options;
        options.window = window;
        options.delay_ms = delay;
        await_complete(path, transmit(path, input.fd, original, limit, options, show_stats));
    } else
        receive_file(path, *file, total, capacity, delay);
    if (udp.fd >= 0) {
        close(udp.fd);
        udp.fd = -1;
    }
    try {
        channel.expect(Control::Close, 5000000);
    } catch (const std::exception& error) {
        throw std::runtime_error(std::string("completion was published but SSH close was not "
                                             "confirmed: ") +
                                 error.what());
    }
}
// scp's rule: a colon before any slash marks [user@]host:path.
inline bool remote_spec(const std::string& text) {
    size_t colon = text.find(':');
    return colon != std::string::npos && colon && text.find('/') > colon;
}
// Requirement: select direct authenticated UDP when available and explicitly use SSH/TCP otherwise.
inline void remote_copy(const std::string& source, const std::string& target,
                        const RemoteOptions& options) {
    bool download = remote_spec(source);
    require(!(download && remote_spec(target)),
            "copying between two remote hosts is not supported");
    require(download || remote_spec(target),
            "one of SOURCE or DEST must be [user@]host:path");
    const std::string& remote = download ? source : target;
    const std::string& local = download ? target : source;
    diagnostic(std::string("role=client startup direction=") + (download ? "download" : "upload") +
               " mode=" + std::to_string(unsigned(options.mode)) +
               " window=" + std::to_string(options.window) +
               " receive-chunks=" + std::to_string(options.receive_chunks));
    size_t colon = remote.find(':');
    require(colon + 1 < remote.size(), "remote path must be [user@]host:path");
    std::string host = remote.substr(0, colon), remote_path = remote.substr(colon + 1);
    require(remote_path.size() <= 4096 && remote_path.find('\0') == std::string::npos,
            "invalid remote path");
    require(!download || options.bbr,
            "--cc=fixed applies to uploads; downloads use the adaptive controller");
    // Local problems (unreadable source, unusable destination) fail before SSH starts.
    ScopedFd input;
    struct stat original {};
    std::unique_ptr<OutputFile> file;
    uint64_t total = 0;
    if (download)
        file = std::make_unique<OutputFile>(local);
    else {
        input.fd = open(local.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        require(input.fd >= 0 && fstat(input.fd, &original) == 0 && S_ISREG(original.st_mode) &&
                    original.st_size >= 0,
                "source must be a regular file");
        total = uint64_t(original.st_size);
    }
    uint64_t session = get(random_bytes(8), 0, 8);
    Bytes keys = random_bytes(64);
    PacketCipher outgoing(Bytes(keys.begin(), keys.begin() + 32)),
        incoming(Bytes(keys.begin() + 32, keys.end()));
    diagnostic("client local bytes=" + std::to_string(total));
    SshProcess ssh(host, options.ssh_program, options.remote_program, options.ssh_config);
    FrameChannel channel(ssh.fd(), ssh.fd());
    ScopedFd udp(options.mode == RemoteMode::Ssh ? -1 : udp_socket());
    diagnostic("client local UDP port=" + std::to_string(udp.fd >= 0 ? udp_port(udp.fd) : 0));
    Bytes init(96 + remote_path.size());
    put(init, 0, 0x55465333, 4);
    put(init, 4, total, 8);
    put(init, 12, session, 8);
    init[20] = uint8_t(options.mode);
    put(init, 21, options.window, 2);
    put(init, 23, options.receive_chunks, 2);
    put(init, 25, options.delay_ms, 2);
    std::copy(keys.begin(), keys.end(), init.begin() + 27);
    put(init, 91, remote_path.size(), 2);
    put(init, 93, udp.fd >= 0 ? udp_port(udp.fd) : 0, 2);
    init[95] = uint8_t((download ? INIT_DOWNLOAD : 0) | (options.stats ? INIT_STATS : 0));
    std::copy(remote_path.begin(), remote_path.end(), init.begin() + 96);
    diagnostic("client sending INIT; waiting for remote helper READY");
    channel.send(Control::Init, init);
    OPENSSL_cleanse(keys.data(), keys.size());
    OPENSSL_cleanse(init.data() + 27, 64);
    auto ready = channel.expect(Control::Ready, 30000000).bytes;
    require(ready.size() == 10 && (download || get(ready, 0, 8) <= total),
            "invalid remote ready response");
    if (download)
        total = get(ready, 0, 8);
    diagnostic("client READY received remote UDP port=" + std::to_string(get(ready, 8, 2)));
    sockaddr_in peer{};
    bool direct = false;
    if (options.mode != RemoteMode::Ssh && udp.fd >= 0 && get(ready, 8, 2)) {
        std::string hostname =
            options.udp_address.empty()
                ? host.substr(host.find('@') == std::string::npos ? 0 : host.find('@') + 1)
                : options.udp_address;
        bool resolved = resolve_udp(hostname, uint16_t(get(ready, 8, 2)), peer);
        diagnostic("client resolve host=" + hostname + " success=" + std::to_string(resolved));
        if (resolved) {
            diagnostic("client probing remote UDP endpoint=" + endpoint(peer));
            // Requirement: bidirectional probes test full-sized encrypted datagrams before choosing native UDP.
            Bytes challenge(PacketCipher::MAX_PLAIN - 1);
            auto nonce = random_bytes(16);
            std::copy(nonce.begin(), nonce.end(), challenge.begin());
            Time until = session_now() + 1200000, next = 0;
            while (session_now() < until && !direct) {
                auto now = session_now();
                if (now >= next) {
                    bool sent =
                        raw_send(udp.fd, peer, encrypted_record(outgoing, 1, challenge), true);
                    diagnostic("client UDP probe sent=" + std::to_string(sent));
                    next = now + 200000;
                }
                Bytes sealed, plain;
                sockaddr_in from{};
                if (raw_receive(udp.fd, sealed, from)) {
                    bool expected_peer = same_peer(peer, from);
                    bool authenticated = expected_peer && incoming.open(sealed, plain);
                    if (authenticated && plain[0] == 3) {
                        diagnostic("client received helper punch from=" + endpoint(from));
                        continue;
                    }
                    direct = authenticated && plain.size() == PacketCipher::MAX_PLAIN &&
                             plain[0] == 1 && Bytes(plain.begin() + 1, plain.end()) == challenge;
                    diagnostic("client UDP probe reply from=" + endpoint(from) +
                               " bytes=" + std::to_string(sealed.size()) +
                               " expected-peer=" + std::to_string(expected_peer) +
                               " authenticated=" + std::to_string(authenticated) +
                               " challenge-matched=" + std::to_string(direct));
                }
                // Error frames throw inside next(); nothing else is valid before SELECT.
                Frame unexpected;
                require(!channel.next(unexpected), "unexpected control message during UDP probe");
                if (!direct)
                    channel.wait(1000, udp.fd);
            }
        }
    }
    diagnostic("client UDP negotiation complete reachable=" + std::to_string(direct));
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
    DataPath path{channel, udp.fd, peer, outgoing, incoming, direct, session};
    if (download) {
        // The helper sends; its --stats lines arrive on this terminal through SSH stderr.
        receive_file(path, *file, total, options.receive_chunks, options.delay_ms);
        try {
            channel.send(Control::Close);
            channel.finish_writes();
            ssh.success();
        } catch (const std::exception& error) {
            throw std::runtime_error(
                std::string("download verified and saved but SSH shutdown failed: ") +
                error.what());
        }
        std::cout << "Complete: " << total << " bytes received, verified with SHA-256 and saved\n";
        return;
    }
    Bytes finish = transmit(path, input.fd, original, get(ready, 0, 8), options, options.stats);
    bool confirmed = false;
    try {
        await_complete(path, finish);
        confirmed = true;
        channel.send(Control::Close);
        channel.finish_writes();
        ssh.success();
    } catch (const std::exception& error) {
        throw std::runtime_error(
            std::string(confirmed ? "destination confirmed but SSH shutdown failed: "
                                  : "completion unconfirmed: destination may exist: ") +
            error.what());
    }
    std::cout << "Complete: " << total << " bytes verified with SHA-256 and finalized\n";
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
