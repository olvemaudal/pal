#ifndef PAL_TYPE3_MESSAGE_HPP_INCLUDED
#define PAL_TYPE3_MESSAGE_HPP_INCLUDED

#include "ntlm_message.hpp"

#include <iosfwd>
#include <string>

namespace pal {
    
    class type3_message : public ntlm_message {
    public:
        type3_message(
            const std::vector<uint8_t> & lm_response,
            const std::vector<uint8_t> & nt_response,
            const std::string & user,                 
            uint32_t ssp_flags);
        virtual std::vector<uint8_t> as_bytes() const;
        std::string debug_print() const;
    private:
        const std::vector<uint8_t> lm_response_;
        const std::vector<uint8_t> nt_response_;
        const std::string domain_;
        const std::string user_;
        const std::string workstation_;
        const std::vector<uint8_t> session_key_;
        const uint32_t ssp_flags_;
    };
    
}

#endif

