#include "type2_message.hpp"

#include "tools.hpp"

#include <stdexcept>
#include <algorithm>

/*
 * See http://davenport.sourceforge.net/ntlm.html
 * 
 * Type 2 Message
 *
 *   0  NTLMSSP Signature                 {'N','T','L','M','S','S','S','\0'}
 *   8  NTLM Message Type                 {0x02,0x00,0x00,0x00}
 *  12  Target Name                       (security buffer)
 *  20  Flags                             uint32 as little endian
 *  24  Challenge                         8 bytes / uint64 as little endian
 * (32) Context (optional)                8 bytes (2xlong)
 * (40) Target Information                (security buffer)
 * (48) (start of datablock)
 *      targetname
 *      targetinfo
 *          server (type=0x0100, len, data)
 *          domain (type=0x0200, len, data)
 *          dnsserver (type=0x0300, len, data)
 *          dnsdomain (type=0x0400, len, data)
 *          type5 (type=0x0500, len, data)   // unknown role
 *          <terminator> (type=0,len=0)
 */

pal::type2_message::type2_message(const std::vector<uint8_t> & buffer)
    : buffer_(buffer) 
{
    const std::size_t min_type2_buffer_size = 32;
    if (buffer.size() < min_type2_buffer_size)
        throw std::invalid_argument("not a type2 message, message too short");
    const uint8_t prefix[12] = {
        'N','T','L','M','S','S','P','\0',
        0x02,0x00,0x00,0x00
    };
    if (!std::equal(prefix, prefix + sizeof prefix, buffer.begin()))
        throw std::invalid_argument("not a type2 message, invalid prefix");
}

uint32_t pal::type2_message::ssp_flags() const
{
    const std::size_t ssp_flags_offset = 20;
    return pal::read_uint32_from_little_endian(&buffer_[ssp_flags_offset]);
}

uint64_t pal::type2_message::challenge() const
{
    const std::size_t challenge_offset = 24;
    return pal::read_uint64_from_little_endian(&buffer_[challenge_offset]);
}

std::vector<uint8_t> pal::type2_message::as_bytes() const
{
    return buffer_;
}

