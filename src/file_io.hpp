#pragma once
#include "wire.hpp"
#include "crypto.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <exception>
#include <mutex>
#include <thread>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>

namespace ufcp {
// Requirement: publish verified files like scp (replace an existing file), and remove temporary output on normal failure.
class OutputFile {
    std::string destination_, temporary_;
    int fd_ = -1;

  public:
    explicit OutputFile(const std::string& destination)
        : destination_(destination), temporary_(destination + ".part") {
        struct stat existing {};
        bool replace = stat(destination_.c_str(), &existing) == 0;
        require(!replace || !S_ISDIR(existing.st_mode), "destination is a directory");
        require(!replace || S_ISREG(existing.st_mode), "destination exists and is not a regular file");
        fd_ = open(temporary_.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        require(fd_ >= 0, "cannot create temporary output");
        // Like scp, an overwritten file keeps its permission bits; new files stay owner-only.
        if (replace)
            require(fchmod(fd_, existing.st_mode & 07777) == 0, "cannot copy destination permissions");
    }
    ~OutputFile() {
        close(fd_);
        unlink(temporary_.c_str());
    }
    OutputFile(const OutputFile&) = delete;
    OutputFile& operator=(const OutputFile&) = delete;
    int fd() const {
        return fd_;
    }
    void publish() {
        // rename atomically replaces any existing destination, so readers never see a partial file.
        require(rename(temporary_.c_str(), destination_.c_str()) == 0, "cannot finalize destination");
    }
};
// Requirement: bounded producer/consumer queues keep blocking disk operations outside the network loop.
class FileQueue {
    std::mutex mutex_;
    std::condition_variable changed_;
    std::deque<Bytes> queue_;
    bool closed_ = false, canceled_ = false;
    std::exception_ptr error_;

  public:
    static constexpr size_t CAPACITY = 16;
    bool push(Bytes bytes) {
        std::unique_lock<std::mutex> lock(mutex_);
        changed_.wait(lock, [&] { return canceled_ || closed_ || queue_.size() < CAPACITY; });
        if (canceled_ || closed_)
            return false;
        queue_.push_back(std::move(bytes));
        changed_.notify_all();
        return true;
    }
    bool try_push(const Bytes& bytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_ || canceled_ || queue_.size() == CAPACITY)
            return false;
        queue_.push_back(bytes);
        changed_.notify_all();
        return true;
    }
    bool pop(Bytes& bytes, bool wait) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (wait)
            changed_.wait(lock, [&] { return canceled_ || closed_ || !queue_.empty(); });
        if (canceled_ || queue_.empty())
            return false;
        bytes = std::move(queue_.front());
        queue_.pop_front();
        changed_.notify_all();
        return true;
    }
    void close() {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
        changed_.notify_all();
    }
    void cancel() {
        std::lock_guard<std::mutex> lock(mutex_);
        canceled_ = true;
        changed_.notify_all();
    }
    void fail() {
        std::lock_guard<std::mutex> lock(mutex_);
        error_ = std::current_exception();
        canceled_ = true;
        changed_.notify_all();
    }
    void check() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (error_)
            std::rethrow_exception(error_);
    }
};
inline bool same_source(const struct stat& a, const struct stat& b) {
    return a.st_size == b.st_size && a.st_mtim.tv_sec == b.st_mtim.tv_sec &&
           a.st_mtim.tv_nsec == b.st_mtim.tv_nsec && a.st_ctim.tv_sec == b.st_ctim.tv_sec &&
           a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}
class FileReader {
    FileQueue queue_;
    std::atomic<bool> done_{false};
    uint32_t digest_ = ~0u;
    Bytes hash_;
    std::thread thread_;

  public:
    FileReader(int fd, struct stat original, unsigned delay_ms)
        : thread_([this, fd, original, delay_ms] {
              try {
                  Sha256 hash;
                  uint64_t remaining = uint64_t(original.st_size);
                  while (remaining) {
                      Bytes bytes(size_t(std::min<uint64_t>(remaining, PAYLOAD)));
                      size_t read_bytes = 0;
                      while (read_bytes < bytes.size()) {
                          auto n = read(fd, bytes.data() + read_bytes, bytes.size() - read_bytes);
                          if (n < 0 && errno == EINTR)
                              continue;
                          require(n > 0, "source read failed or source changed");
                          read_bytes += size_t(n);
                      }
                      digest_ = crc(digest_, bytes.data(), bytes.size());
                      remaining -= bytes.size();
                      hash.update(bytes);
                      if (delay_ms)
                          std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
                      if (!queue_.push(std::move(bytes)))
                          return;
                  }
                  struct stat current {};
                  require(fstat(fd, &current) == 0 && same_source(original, current),
                          "source changed during transfer");
                  hash_ = hash.finish();
                  queue_.close();
                  done_.store(true);
              } catch (...) {
                  queue_.fail();
              }
          }) {}
    // The caller owns the descriptor and must keep it open until this worker has joined.
    ~FileReader() {
        queue_.cancel();
        thread_.join();
    }
    bool pop(Bytes& bytes) {
        queue_.check();
        return queue_.pop(bytes, false);
    }
    bool done() {
        queue_.check();
        return done_.load();
    }
    uint32_t digest() {
        require(done(), "source digest unavailable");
        return ~digest_;
    }
    const Bytes& hash() {
        require(done(), "source hash unavailable");
        return hash_;
    }
};
class FileWriter {
    FileQueue queue_;
    std::atomic<uint64_t> written_{0};
    std::atomic<bool> done_{false};
    uint32_t digest_ = ~0u;
    Bytes hash_;
    std::thread thread_;

  public:
    FileWriter(int fd, unsigned delay_ms)
        : thread_([this, fd, delay_ms] {
              try {
                  Sha256 hash;
                  Bytes bytes;
                  while (queue_.pop(bytes, true)) {
                      if (delay_ms)
                          std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
                      size_t written = 0;
                      while (written < bytes.size()) {
                          auto n = write(fd, bytes.data() + written, bytes.size() - written);
                          if (n < 0 && errno == EINTR)
                              continue;
                          require(n > 0, "destination write failed");
                          written += size_t(n);
                      }
                      digest_ = crc(digest_, bytes.data(), bytes.size());
                      hash.update(bytes);
                      written_.fetch_add(bytes.size());
                  }
                  hash_ = hash.finish();
                  done_.store(true);
              } catch (...) {
                  queue_.fail();
              }
          }) {}
    ~FileWriter() {
        queue_.cancel();
        thread_.join();
    }
    bool push(const Bytes& bytes) {
        queue_.check();
        return queue_.try_push(bytes);
    }
    // Only completed writes release receiver credit; queued bytes still occupy receive capacity.
    uint64_t written() {
        queue_.check();
        return written_.load();
    }
    void close() {
        queue_.close();
    }
    bool done() {
        queue_.check();
        return done_.load();
    }
    uint32_t digest() {
        require(done(), "destination digest unavailable");
        return ~digest_;
    }
    const Bytes& hash() {
        require(done(), "destination hash unavailable");
        return hash_;
    }
};
} // namespace ufcp
