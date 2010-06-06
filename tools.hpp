#ifndef PAL_TOOLS_HPP_INCLUDED
#define PAL_TOOLS_HPP_INCLUDED

#include <stdint.h>
#include <string>
#include <vector>

namespace pal
{
    std::string as_base64_string(const std::vector<uint8_t> & buf);
    std::vector<uint8_t> as_bytes_from_base64_string(const std::string & base64_string);
    std::string as_hex_string(const std::vector<uint8_t> & buf);
    std::vector<uint8_t> as_bytes_from_hex_string(const std::string & hex_string);
    std::string as_hex_dump(const std::vector<uint8_t> & bytes);
    std::vector<uint8_t> as_unicode(const std::string & str);
    std::vector<uint8_t> as_bytes(const std::string & str);

    void write_little_endian_from_uint16(uint8_t * ptr, uint16_t value);
    void write_little_endian_from_uint32(uint8_t * ptr, uint32_t value);
    void write_little_endian_from_uint64(uint8_t * ptr, uint64_t value);
    uint16_t read_uint16_from_little_endian(const uint8_t * ptr);
    uint32_t read_uint32_from_little_endian(const uint8_t * ptr);
    uint64_t read_uint64_from_little_endian(const uint8_t * ptr);

    std::vector<uint8_t> rc4(const std::vector<uint8_t> & key, const std::vector<uint8_t> & bytes);
    std::vector<uint8_t> des_encrypt(const std::vector<uint8_t> & key56, const std::vector<uint8_t> & bytes);
    std::vector<uint8_t> md4(const std::vector<uint8_t> & bytes);
}

#endif
