#pragma once
#include "wire.hpp"
#include <chrono>
#include <array>
#include <deque>
#include <string>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ufcp {
inline Time session_now() { return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
struct ScopedFd {
    int fd;
    explicit ScopedFd(int value = -1) : fd(value) {}
    ~ScopedFd() { if (fd >= 0) close(fd); }
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;
};
inline void nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    require(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0, "cannot make session descriptor nonblocking");
}
enum class Control : uint8_t { Init = 1, Ready, Select, Selected, Packet, Finish, Complete, Error, Close };
struct Frame { Control type; Bytes bytes; };
// Requirement: bounded nonblocking framing preserves datagrams and control messages across the SSH byte stream.
class FrameChannel {
    int input_, output_;
    Bytes input_bytes_;
    std::deque<Bytes> output_frames_;
    size_t output_bytes_ = 0, written_ = 0;
public:
    static constexpr size_t MAX_FRAME = 8192, QUEUE = 128 * 1024;
    FrameChannel(int input, int output) : input_(input), output_(output) { nonblocking(input_); nonblocking(output_); }
    // Reserve one control frame so queued payload cannot prevent completion or error reporting.
    bool room(size_t bytes = MAX_FRAME) const { return bytes + MAX_FRAME + 5 <= QUEUE - output_bytes_; }
    bool empty() const { return output_frames_.empty(); }
    void send(Control type, const Bytes& payload = {}) {
        require(payload.size() + 1 <= MAX_FRAME && payload.size() + 5 <= QUEUE - output_bytes_, "SSH frame queue exhausted");
        Bytes frame(5 + payload.size()); put(frame, 0, payload.size() + 1, 4); frame[4] = uint8_t(type);
        std::copy(payload.begin(), payload.end(), frame.begin() + 5);
        output_bytes_ += frame.size(); output_frames_.push_back(std::move(frame));
    }
    void flush() {
        while (!output_frames_.empty()) {
            auto& frame = output_frames_.front();
            auto n = write(output_, frame.data() + written_, frame.size() - written_);
            if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) return;
            require(n > 0, "SSH channel closed while writing");
            written_ += size_t(n); output_bytes_ -= size_t(n);
            if (written_ == frame.size()) { written_ = 0; output_frames_.pop_front(); }
        }
    }
    bool next(Frame& frame) {
        for (int attempt = 0; attempt < 2; ++attempt) {
            if (input_bytes_.size() >= 4) {
                size_t size = size_t(get(input_bytes_, 0, 4));
                require(size && size <= MAX_FRAME, "invalid SSH frame length");
                if (input_bytes_.size() >= size + 4) {
                    require(input_bytes_[4] >= uint8_t(Control::Init) && input_bytes_[4] <= uint8_t(Control::Close), "invalid SSH frame type");
                    frame = {Control(input_bytes_[4]), Bytes(input_bytes_.begin() + 5, input_bytes_.begin() + 4 + size)};
                    input_bytes_.erase(input_bytes_.begin(), input_bytes_.begin() + 4 + size);
                    if (frame.type == Control::Error) throw std::runtime_error("remote error: " + std::string(frame.bytes.begin(), frame.bytes.end()));
                    return true;
                }
            }
            if (attempt) return false;
            std::array<uint8_t, MAX_FRAME + 4> buffer{};
            auto n = read(input_, buffer.data(), buffer.size() - input_bytes_.size());
            if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) return false;
            require(n > 0, "SSH channel closed before session completion");
            input_bytes_.insert(input_bytes_.end(), buffer.begin(), buffer.begin() + n);
        }
        return false;
    }
    void wait(Time delay = 1000, int udp = -1) {
        pollfd descriptors[3]{{input_, POLLIN, 0}, {output_, short(empty() ? 0 : POLLOUT), 0}, {udp, POLLIN, 0}};
        timespec duration{time_t(delay / 1000000), long(delay % 1000000 * 1000)};
        int result = ppoll(descriptors, 3, &duration, nullptr);
        require(result >= 0 || errno == EINTR, "session poll failed");
    }
    Frame expect(Control type, Time timeout = 15000000) {
        Time deadline = session_now() + timeout;
        while (session_now() < deadline) {
            flush(); Frame frame;
            if (next(frame)) { require(frame.type == type, "unexpected SSH control message"); return frame; }
            wait();
        }
        throw std::runtime_error("SSH session timeout");
    }
    void finish_writes(Time timeout = 2000000) {
        Time deadline = session_now() + timeout;
        while (!empty() && session_now() < deadline) { flush(); if (!empty()) wait(); }
        require(empty(), "SSH write timeout");
    }
};
inline std::string shell_quote(const std::string& text) {
    require(!text.empty() && text.size() <= 4096 && text.find('\0') == std::string::npos, "invalid remote program path");
    std::string result = "'";
    for (char c : text) { if (c == '\'') result += "'\\''"; else result += c; }
    return result + "'";
}
// Requirement: delegate authentication and host-key checks to OpenSSH without interpolating remote file paths.
class SshProcess {
    pid_t pid_ = -1;
    int fd_ = -1;
public:
    SshProcess(const std::string& host, const std::string& program, const std::string& remote_program, const std::string& config) {
        require(!host.empty() && host[0] != '-' && host.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@") == std::string::npos, "invalid SSH destination");
        int sockets[2]; require(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0, "cannot create SSH channel");
        ScopedFd parent(sockets[0]), child(sockets[1]);
        std::vector<std::string> arguments{program, "-T", "-a", "-x", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3"};
        if (!config.empty()) { arguments.push_back("-F"); arguments.push_back(config); }
        arguments.push_back(host); arguments.push_back(shell_quote(remote_program) + " --helper");
        std::vector<char*> argv;
        for (auto& argument : arguments) argv.push_back(&argument[0]);
        argv.push_back(nullptr);
        pid_ = fork(); require(pid_ >= 0, "cannot start SSH client");
        if (!pid_) {
            if (dup2(child.fd, STDIN_FILENO) < 0 || dup2(child.fd, STDOUT_FILENO) < 0) _exit(126);
            close(parent.fd); close(child.fd); execvp(argv[0], argv.data()); _exit(127);
        }
        fd_ = parent.fd; parent.fd = -1;
    }
    int fd() const { return fd_; }
    void success() {
        int status = 0; Time deadline = session_now() + 3000000;
        while (session_now() < deadline) {
            pid_t result = waitpid(pid_, &status, WNOHANG);
            if (result == pid_) { pid_ = -1; require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "SSH helper failed after confirmed completion"); return; }
            require(result >= 0 || errno == EINTR, "cannot wait for SSH client"); usleep(1000);
        }
        throw std::runtime_error("SSH client did not exit after confirmed completion");
    }
    ~SshProcess() {
        if (fd_ >= 0) close(fd_);
        if (pid_ > 0) {
            int status = 0;
            for (unsigned i = 0; i < 100; ++i) {
                if (waitpid(pid_, &status, WNOHANG) == pid_) return;
                usleep(1000);
            }
            kill(pid_, SIGTERM);
            for (unsigned i = 0; i < 100; ++i) {
                if (waitpid(pid_, &status, WNOHANG) == pid_) return;
                usleep(1000);
            }
            kill(pid_, SIGKILL); while (waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
        }
    }
};
}
