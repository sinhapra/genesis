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
#include <cstring>
#include <fcntl.h>

namespace ufcp {
// Requirement: publish verified files like scp (replace an existing file), and remove temporary output on normal failure.
class OutputFile {
    std::string destination_, temporary_;
    int fd_ = -1;
    bool published_ = false;
    // A unique hidden name beside the destination, ".NAME.XXXXXXXX.part". Exclusive creation with a
    // random suffix means files left by crashed runs and concurrent copies never block a new copy.
    static std::string temporary_name(const std::string& destination) {
        size_t slash = destination.rfind('/');
        std::string directory = slash == std::string::npos ? "" : destination.substr(0, slash + 1);
        std::string name = slash == std::string::npos ? destination : destination.substr(slash + 1);
        static const char digits[] = "abcdefghijklmnopqrstuvwxyz0123456789";
        std::string suffix;
        for (uint8_t byte : random_bytes(8))
            suffix += digits[byte % 36];
        return directory + "." + name.substr(0, 200) + "." + suffix + ".part";
    }

  public:
    explicit OutputFile(const std::string& destination) : destination_(destination) {
        struct stat existing {};
        bool replace = stat(destination_.c_str(), &existing) == 0;
        require(!replace || !S_ISDIR(existing.st_mode), "destination is a directory");
        require(!replace || S_ISREG(existing.st_mode),
                "destination exists and is not a regular file");
        for (int attempt = 0; fd_ < 0 && attempt < 8; ++attempt) {
            temporary_ = temporary_name(destination_);
            fd_ = open(temporary_.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (fd_ < 0 && errno != EEXIST)
                break;
        }
        if (fd_ < 0)
            throw std::runtime_error("cannot create temporary output " + temporary_ + ": " +
                                     std::strerror(errno));
        // Like scp, an overwritten file keeps its permission bits; new files stay owner-only.
        if (replace)
            require(fchmod(fd_, existing.st_mode & 07777) == 0,
                    "cannot copy destination permissions");
    }
    ~OutputFile() {
        if (fd_ >= 0)
            close(fd_);
        if (!published_)
            unlink(temporary_.c_str());
    }
    OutputFile(const OutputFile&) = delete;
    OutputFile& operator=(const OutputFile&) = delete;
    int fd() const {
        return fd_;
    }
    const std::string& temporary() const {
        return temporary_;
    }
    void publish() {
        // rename atomically replaces any existing destination, so readers never see a partial file.
        require(rename(temporary_.c_str(), destination_.c_str()) == 0,
                "cannot finalize destination");
        published_ = true;
    }
};
// Disk workers move data in blocks of up to 1 MiB: one read()/write() per block instead of one per
// 1 KiB chunk, which matters on network or virtual filesystems with a high per-call cost.
constexpr size_t DISK_BLOCK = 1 << 20;
// Requirement: bounded producer/consumer queues keep blocking disk operations outside the network loop.
class FileQueue {
    std::mutex mutex_;
    std::condition_variable changed_;
    std::deque<Bytes> queue_;
    bool closed_ = false, canceled_ = false;
    std::exception_ptr error_;

  public:
    // About one disk block of 1 KiB chunks, so workers can batch disk calls.
    static constexpr size_t CAPACITY = 1024;
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
                  Bytes block;
                  while (remaining) {
                      block.resize(size_t(std::min<uint64_t>(remaining, DISK_BLOCK)));
                      size_t read_bytes = 0;
                      while (read_bytes < block.size()) {
                          auto n = read(fd, block.data() + read_bytes, block.size() - read_bytes);
                          if (n < 0 && errno == EINTR)
                              continue;
                          require(n > 0, "source read failed or source changed");
                          read_bytes += size_t(n);
                      }
                      remaining -= block.size();
                      digest_ = crc(digest_, block.data(), block.size());
                      hash.update(block);
                      // Split the block into network chunks; the queue bound still applies per chunk.
                      for (size_t at = 0; at < block.size(); at += PAYLOAD) {
                          size_t size = std::min(PAYLOAD, block.size() - at);
                          if (delay_ms)
                              std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
                          if (!queue_.push(Bytes(block.begin() + at, block.begin() + at + size)))
                              return;
                      }
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
                  Bytes bytes, block;
                  while (queue_.pop(bytes, true)) {
                      // Coalesce chunks that are already queued (never waiting for more) into one write.
                      block.assign(bytes.begin(), bytes.end());
                      size_t chunks = 1;
                      while (block.size() < DISK_BLOCK && queue_.pop(bytes, false)) {
                          block.insert(block.end(), bytes.begin(), bytes.end());
                          ++chunks;
                      }
                      if (delay_ms)
                          std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms * chunks));
                      size_t written = 0;
                      while (written < block.size()) {
                          auto n = write(fd, block.data() + written, block.size() - written);
                          if (n < 0 && errno == EINTR)
                              continue;
                          require(n > 0, "destination write failed");
                          written += size_t(n);
                      }
                      digest_ = crc(digest_, block.data(), block.size());
                      hash.update(block);
                      // Credit is released only for bytes that have actually been written.
                      written_.fetch_add(block.size());
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
