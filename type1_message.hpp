#ifndef PAL_TYPE1_MESSAGE_HPP_INCLUDED
#define PAL_TYPE1_MESSAGE_HPP_INCLUDED

#include "ntlm_message.hpp"

#include <vector>

namespace pal {
    
    class type1_message : public ntlm_message {
        uint32_t ssp_flags_;
    public:
        type1_message(uint32_t ssp_flags);
        virtual std::vector<uint8_t> as_bytes() const;
    };
    
}

#endif

