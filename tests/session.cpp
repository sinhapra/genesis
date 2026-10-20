#include "../src/crypto.hpp"
#include "../src/session_io.hpp"
#include <iostream>

using namespace ufcp;
void check(bool value) { require(value, "session test assertion failed"); }
int main() {
    try {
        auto key = random_bytes(32), different = random_bytes(32);
        PacketCipher sender(key), receiver(key), wrong(different);
        auto first = sender.seal(Bytes{1, 2, 3}); Bytes plain;
        auto bad = first; bad.back() ^= 1;
        check(!receiver.open(bad, plain)); check(plain.empty());
        check(!wrong.open(first, plain)); check(receiver.open(first, plain) && plain == Bytes({1, 2, 3}));
        check(!receiver.open(first, plain));
        auto second = sender.seal(Bytes{7}), third = sender.seal(Bytes{8});
        check(receiver.open(third, plain)); check(receiver.open(second, plain));
        for (unsigned i = 0; i < 1100; ++i) { auto packet = sender.seal(Bytes{9}); check(receiver.open(packet, plain)); }
        check(!receiver.open(second, plain));
        PacketCipher fresh(key); auto forged = sender.seal(Bytes{1}); put(forged, 4, UINT64_MAX, 8);
        check(!fresh.open(forged, plain)); check(fresh.open(first, plain));
        for (size_t n = 0; n < first.size(); ++n) check(!wrong.open(Bytes(first.begin(), first.begin() + n), plain));
        Sha256 hash; hash.update(Bytes{'a', 'b', 'c'}); auto digest = hash.finish();
        const Bytes expected{0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
            0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
        check(digest == expected);
        int sockets[2]; check(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
        ScopedFd a(sockets[0]), b(sockets[1]); FrameChannel input(a.fd, a.fd), output(b.fd, b.fd);
        Bytes encoded{0, 0, 0, 4, uint8_t(Control::Packet), 1, 2, 3}; Frame frame;
        for (size_t i = 0; i < encoded.size(); ++i) {
            check(write(b.fd, &encoded[i], 1) == 1);
            bool ready = input.next(frame); check(ready == (i + 1 == encoded.size()));
        }
        check(frame.type == Control::Packet && frame.bytes == Bytes({1, 2, 3}));
        output.send(Control::Ready, Bytes{4}); output.send(Control::Select, Bytes{2}); output.flush();
        check(input.next(frame) && frame.type == Control::Ready); check(input.next(frame) && frame.type == Control::Select);
        std::cout << "PASS AEAD tampering, wrong keys, nonce/replay ordering, SHA-256 vector, fragmented/coalesced frames\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
