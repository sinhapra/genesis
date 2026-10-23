#pragma once
#include "transport.hpp"

namespace ufcp {
constexpr size_t HEADER = 30, MAX_DATAGRAM = HEADER + 8 + PAYLOAD;
enum Type : uint8_t { START = 1, DATA = 2, FINISH = 3, ACK = 4, PROBE = 5 };
inline void put(Bytes& b, size_t at, uint64_t value, size_t count) {
    require(at <= b.size() && count <= b.size() - at, "wire write outside buffer");
    while (count) {
        b[at + --count] = uint8_t(value);
        value >>= 8;
    }
}
inline uint64_t get(const Bytes& b, size_t at, size_t count) {
    require(at <= b.size() && count <= b.size() - at && count <= 8, "wire read outside buffer");
    uint64_t value = 0;
    for (size_t i = 0; i < count; ++i)
        value = (value << 8) | b[at + i];
    return value;
}
// CRC-32 (IEEE, reflected 0xedb88320) tables for slicing-by-8: same values as the bitwise form,
// about an order of magnitude faster, which matters because every packet and file byte is checked.
struct CrcTables {
    uint32_t table[8][256];
    constexpr CrcTables() : table() {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t value = i;
            for (int j = 0; j < 8; ++j)
                value = (value >> 1) ^ (0xedb88320u & (0u - (value & 1u)));
            table[0][i] = value;
        }
        for (uint32_t i = 0; i < 256; ++i)
            for (int k = 1; k < 8; ++k)
                table[k][i] = (table[k - 1][i] >> 8) ^ table[0][table[k - 1][i] & 0xff];
    }
};
inline constexpr CrcTables CRC_TABLES{};
inline uint32_t crc(uint32_t state, const uint8_t* p, size_t n) {
    const auto& t = CRC_TABLES.table;
    for (; n >= 8; p += 8, n -= 8) {
        uint32_t low = state ^ (uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 |
                                uint32_t(p[3]) << 24);
        state = t[7][low & 0xff] ^ t[6][(low >> 8) & 0xff] ^ t[5][(low >> 16) & 0xff] ^
                t[4][low >> 24] ^ t[3][p[4]] ^ t[2][p[5]] ^ t[1][p[6]] ^ t[0][p[7]];
    }
    while (n--)
        state = (state >> 8) ^ t[0][(state ^ *p++) & 0xff];
    return state;
}
inline uint32_t wire_crc(const Bytes& b) {
    return ~crc(crc(~0u, b.data(), 26), b.data() + HEADER, b.size() - HEADER);
}
inline Bytes packet(Type type, uint64_t session, uint64_t offset, const Bytes& payload = {}) {
    require(payload.size() <= MAX_DATAGRAM - HEADER, "oversized wire payload");
    Bytes b(HEADER + payload.size());
    put(b, 0, 0x55464333,
        4); // Requirement: explicitly serialize the incompatible UFC3 wire version.
    b[4] = type;
    put(b, 8, session, 8);
    put(b, 16, offset, 8);
    put(b, 24, payload.size(), 2);
    std::copy(payload.begin(), payload.end(), b.begin() + HEADER);
    put(b, 26, wire_crc(b), 4);
    return b;
}
inline bool valid(const Bytes& b) {
    return b.size() >= HEADER && b.size() <= MAX_DATAGRAM && get(b, 0, 4) == 0x55464333 &&
           b[4] >= START && b[4] <= PROBE && !b[5] && !b[6] && !b[7] &&
           get(b, 24, 2) == b.size() - HEADER && get(b, 26, 4) == wire_crc(b);
}
inline Bytes data_packet(uint64_t session, const Transmission& value) {
    Bytes payload(8 + value.data.size());
    put(payload, 0, value.number, 8);
    std::copy(value.data.begin(), value.data.end(), payload.begin() + 8);
    return packet(DATA, session, value.offset, payload);
}
inline bool decode_data(const Bytes& b, Transmission& value) {
    if (!valid(b) || b[4] != DATA || b.size() <= HEADER + 8)
        return false;
    value = {get(b, HEADER, 8), get(b, 16, 8), Bytes(b.begin() + HEADER + 8, b.end())};
    return true;
}
inline Bytes ack_packet(uint64_t session, const Ack& ack) {
    require(ack.ranges.size() <= MAX_RANGES && ack.delay >= 0 && ack.delay <= MAX_ACK_DELAY,
            "invalid ACK encoding");
    Bytes payload(14 + ack.ranges.size() * 16);
    payload[0] = DATA;
    put(payload, 1, ack.limit, 8);
    put(payload, 9, uint64_t(ack.delay), 4);
    payload[13] = uint8_t(ack.ranges.size());
    for (size_t i = 0; i < ack.ranges.size(); ++i) {
        put(payload, 14 + i * 16, ack.ranges[i].low, 8);
        put(payload, 22 + i * 16, ack.ranges[i].high, 8);
    }
    return packet(ACK, session, 0, payload);
}
// Requirement: bound ACK parsing work and reject noncanonical ranges before transport processing.
inline bool decode_ack(const Bytes& b, Ack& ack) {
    if (!valid(b) || b[4] != ACK || get(b, 16, 8) || b.size() < HEADER + 14 || b[HEADER] != DATA)
        return false;
    size_t count = b[HEADER + 13];
    if (count > MAX_RANGES || b.size() != HEADER + 14 + count * 16)
        return false;
    Ack parsed;
    parsed.limit = get(b, HEADER + 1, 8);
    parsed.delay = Time(get(b, HEADER + 9, 4));
    if (parsed.delay > MAX_ACK_DELAY)
        return false;
    uint64_t previous = 0;
    for (size_t i = 0; i < count; ++i) {
        Range range{get(b, HEADER + 14 + i * 16, 8), get(b, HEADER + 22 + i * 16, 8)};
        if (!range.low || range.low > range.high ||
            (previous && (previous == UINT64_MAX || range.low <= previous + 1)))
            return false;
        parsed.ranges.push_back(range);
        previous = range.high;
    }
    ack = std::move(parsed);
    return true;
}
} // namespace ufcp
