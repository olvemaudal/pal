#include "type3_message.hpp"

#include "tools.hpp"

#include <algorithm>
#include <cstddef>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <stdexcept>

/*
 * See http://davenport.sourceforge.net/ntlm.html
 * 
 * Type 3 Message
 *
 *   0  NTLMSSP Signature                 "NTLMSSP\0"
 *   8  NTLM Message Type                 {0x03,0x00,0x00,0x00}
 *  12  LM/LMv2 Response                  (security buffer)
 *  20  NTLM/NTLMv2 Response              (security buffer)
 *  28  Domain Name                       (security buffer)
 *  36  User Name                         (security buffer)
 *  44  Workstation Name                  (security buffer)
 * (52) Session Key (optional)            (security buffer)
 * (60) Flags (optional)                  uint32 as little endian
 * (64) (start of datablock)
 *      domain name
 *      user name
 *      workstation name
 *      lm response data
 *      ntlm response data
 *
 * Security buffer: (works like a lookup into the data block)
 *   0  length     (uint16 as little endian)
 *   2  size       (uint16 as little endian)
 *   4  length     (uint32 as little endian)
 */

namespace {
    const std::size_t lm_response_sb_offset = 12;
    const std::size_t nt_response_sb_offset = 20;
    const std::size_t domain_sb_offset = 28;
    const std::size_t user_sb_offset = 36;
    const std::size_t workstation_sb_offset = 44;
    const std::size_t session_key_sb_offset = 52;
    const std::size_t ssp_flags_offset = 60;
    const std::size_t data_block_offset = 64;
    
    const std::size_t lm_response_size = 24;
    const std::size_t nt_response_size = 24;
    const std::size_t session_key_size = 16;
}

pal::type3_message::type3_message(
    const std::vector<uint8_t> & lm_response, 
    const std::vector<uint8_t> & nt_response,
    const std::string & user,
    uint32_t ssp_flags)
    :
    lm_response_(lm_response),
    nt_response_(nt_response),
    domain_(),
    user_(user),
    workstation_(),
    session_key_(session_key_size),
    ssp_flags_(ssp_flags)
{
    if (lm_response_.size() != lm_response_size)
        throw std::invalid_argument("invalid size of lm_response");
    if (nt_response_.size() != nt_response_size)
        throw std::invalid_argument("invalid size of nt_response");
}

namespace {
    void append_data(
        std::vector<uint8_t> & to,
        std::size_t offset,
        const std::vector<uint8_t> & from)
    {
        const std::size_t data_offset = to.end() - to.begin();
        std::copy(from.begin(), from.end(), std::back_inserter(to));
        pal::write_little_endian_from_uint16(&to[offset+0], from.size());
        pal::write_little_endian_from_uint16(&to[offset+2], from.size());
        pal::write_little_endian_from_uint32(&to[offset+4], data_offset);
    }
}

std::vector<uint8_t> pal::type3_message::as_bytes() const
{
    uint8_t prefix[12] = {
        'N','T','L','M','S','S','P','\0',
        0x03,0x00,0x00,0x00
    };
    std::vector<uint8_t> buffer(prefix, prefix + sizeof prefix);
    buffer.resize(data_block_offset);
    pal::write_little_endian_from_uint32(&buffer[ssp_flags_offset], ssp_flags_);

    append_data(buffer, lm_response_sb_offset, lm_response_);
    append_data(buffer, nt_response_sb_offset, nt_response_);
    append_data(buffer, domain_sb_offset, pal::as_bytes(domain_));
    append_data(buffer, user_sb_offset, pal::as_bytes(user_));
    append_data(buffer, workstation_sb_offset, pal::as_bytes(workstation_));
    append_data(buffer, session_key_sb_offset, session_key_);

    return buffer;
}

std::string pal::type3_message::debug_print() const
{
    std::stringstream stm;
    stm << "### type3_message:" << '\n'
        << pal::as_hex_dump(as_bytes())
        << "lmResponse = " << pal::as_hex_string(lm_response_)
        << "\nntResponse = " << pal::as_hex_string(nt_response_)
        << "\ndomain = " << domain_
        << "\nuser = " << user_
        << "\nworkstation = " << workstation_
        << "\nsessionKey = " << pal::as_hex_string(session_key_)
        << std::hex << std::setw(8) << std::setfill('0') 
        << "\nsspFlags = " << ssp_flags_;
    return stm.str();
}

