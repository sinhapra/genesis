#pragma once
#include "wire.hpp"
#include <array>
#include <bitset>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

namespace ufcp {
inline Bytes random_bytes(size_t size) {
    require(size <= 8192, "random request too large"); Bytes bytes(size);
    require(RAND_bytes(bytes.data(), int(size)) == 1, "secure randomness unavailable"); return bytes;
}
// Requirement: use the established OpenSSL SHA-256 implementation for authenticated file completion.
class Sha256 {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context_{EVP_MD_CTX_new(), EVP_MD_CTX_free};
public:
    Sha256() { require(context_ && EVP_DigestInit_ex(context_.get(), EVP_sha256(), nullptr) == 1, "SHA-256 initialization failed"); }
    void update(const Bytes& bytes) { require(EVP_DigestUpdate(context_.get(), bytes.data(), bytes.size()) == 1, "SHA-256 update failed"); }
    Bytes finish() {
        Bytes bytes(32); unsigned length = 0;
        require(EVP_DigestFinal_ex(context_.get(), bytes.data(), &length) == 1 && length == 32, "SHA-256 finalization failed"); return bytes;
    }
};
// Requirement: separate random directional keys, unique nonces, and bounded authenticated replay tracking protect UDP.
class PacketCipher {
    std::array<uint8_t, 32> key_{};
    uint64_t next_ = 1, highest_ = 0;
    std::bitset<1024> replay_;
public:
    static constexpr size_t OVERHEAD = 28, MAX_PLAIN = MAX_DATAGRAM + 1, MAX_SEALED = MAX_PLAIN + OVERHEAD;
    explicit PacketCipher(const Bytes& key) {
        require(key.size() == key_.size(), "invalid session key"); std::copy(key.begin(), key.end(), key_.begin());
    }
    ~PacketCipher() { OPENSSL_cleanse(key_.data(), key_.size()); }
    PacketCipher(const PacketCipher&) = delete;
    PacketCipher& operator=(const PacketCipher&) = delete;
    Bytes seal(const Bytes& plain) {
        require(!plain.empty() && plain.size() <= MAX_PLAIN && next_ != UINT64_MAX, "invalid encrypted datagram or nonce exhaustion");
        Bytes sealed(12 + plain.size() + 16); put(sealed, 0, 0x55464531, 4); put(sealed, 4, next_++, 8);
        std::array<uint8_t, 12> nonce{}; std::copy(sealed.begin() + 4, sealed.begin() + 12, nonce.begin() + 4);
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        int length = 0, written = 0;
        require(context && EVP_EncryptInit_ex(context.get(), EVP_chacha20_poly1305(), nullptr, key_.data(), nonce.data()) == 1 &&
            EVP_EncryptUpdate(context.get(), nullptr, &length, sealed.data(), 12) == 1 &&
            EVP_EncryptUpdate(context.get(), sealed.data() + 12, &written, plain.data(), int(plain.size())) == 1 &&
            EVP_EncryptFinal_ex(context.get(), sealed.data() + 12 + written, &length) == 1 &&
            written + length == int(plain.size()) &&
            EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_GET_TAG, 16, sealed.data() + 12 + plain.size()) == 1, "UDP encryption failed");
        return sealed;
    }
    bool open(const Bytes& sealed, Bytes& plain) {
        plain.clear();
        if (sealed.size() <= OVERHEAD || sealed.size() > MAX_SEALED || get(sealed, 0, 4) != 0x55464531) return false;
        uint64_t number = get(sealed, 4, 8);
        if (!number || (number <= highest_ && (highest_ - number >= replay_.size() || replay_[size_t(highest_ - number)]))) return false;
        std::array<uint8_t, 12> nonce{}; std::copy(sealed.begin() + 4, sealed.begin() + 12, nonce.begin() + 4);
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        require(bool(context), "UDP decryption allocation failed");
        size_t size = sealed.size() - OVERHEAD; plain.resize(size); int length = 0, written = 0;
        bool ok = EVP_DecryptInit_ex(context.get(), EVP_chacha20_poly1305(), nullptr, key_.data(), nonce.data()) == 1 &&
            EVP_DecryptUpdate(context.get(), nullptr, &length, sealed.data(), 12) == 1 &&
            EVP_DecryptUpdate(context.get(), plain.data(), &written, sealed.data() + 12, int(size)) == 1 &&
            EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(sealed.data() + 12 + size)) == 1 &&
            EVP_DecryptFinal_ex(context.get(), plain.data() + written, &length) == 1 && written + length == int(size);
        if (!ok) { OPENSSL_cleanse(plain.data(), plain.size()); plain.clear(); return false; }
        // Advance replay state only after authentication; forged sequence numbers must not discard valid packets.
        if (number > highest_) {
            uint64_t distance = number - highest_;
            if (distance >= replay_.size()) replay_.reset(); else replay_ <<= size_t(distance);
            highest_ = number;
        }
        replay_.set(size_t(highest_ - number)); return true;
    }
};
}
