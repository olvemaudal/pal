#include "type1_message.hpp"

#include "tools.hpp"

#include <cstddef>

/*
 * See http://davenport.sourceforge.net/ntlm.html
 * 
 * Type 1 Message
 *
 *   0  NTLMSSP Signature                 "NTLMSSP\0"
 *   8  NTLM Message Type                 {0x01,0x00,0x00,0x00}
 *  12  Flags                             uint32 as little endian
 * (16) Supplied Domain (optional)        (security buffer)
 * (24) Supplied Workstation (optional)   (security buffer)
 * (32) (start of datablock) if required
 */

pal::type1_message::type1_message(uint32_t ssp_flags)
    : ssp_flags_(ssp_flags)
{
}

std::vector<uint8_t> pal::type1_message::as_bytes() const
{
    uint8_t message[16] = {
        'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0',
        0x01, 0x00, 0x00, 0x00, 0, 0, 0, 0
    };
    const std::size_t ssp_flags_offset = 12;
    pal::write_little_endian_from_uint32(&message[ssp_flags_offset], ssp_flags_);
    return std::vector<uint8_t>(message, message + sizeof message);
}
