#ifndef PAL_PAL_INTERNAL_HPP_INCLUDED
#define PAL_PAL_INTERNAL_HPP_INCLUDED

#include "pal.hpp"

namespace pal {

    std::vector<uint8_t> create_password_hash(const std::string & password);
    std::vector<uint8_t> create_nt_response(const std::vector<uint8_t> & password_hash,
                                            uint64_t challenge);
    std::vector<uint8_t> create_session_key();
    std::vector<uint8_t> create_encrypted_session_key(const std::vector<uint8_t> & password_hash,
                                                      const std::vector<uint8_t> & session_key);
    std::vector<uint8_t> calculate_lm_response(const std::string & password,
                                               uint64_t challenge);

}

#endif
