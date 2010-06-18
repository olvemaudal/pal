#ifndef PAL_PAL_HPP_INCLUDED
#define PAL_PAL_HPP_INCLUDED

#include "ntlm_message.hpp"

#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

namespace pal {

    std::auto_ptr<ntlm_message> create_ntlm_request();
    std::auto_ptr<ntlm_message> create_ntlm_challenge(
        const std::vector<uint8_t> & challenge_as_bytes);
    std::auto_ptr<ntlm_message> create_ntlm_response(
        const std::string & username,
        const std::string & password,
        const ntlm_message & challenge);

    std::vector<uint8_t> as_bytes_from_base64_string(const std::string & str);
    std::string as_base64_string(const std::vector<uint8_t> & data);

}

#endif
