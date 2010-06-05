#ifndef PAL_TYPE1_MESSAGE_HPP
#define PAL_TYPE1_MESSAGE_HPP

#include "ntlm_message.hpp"

namespace pal {
    
    class type1_message : public ntlm_message {
    public:
        explicit type1_message(uint32_t ssp_flags);
        virtual std::vector<uint8_t> as_bytes() const;
    private:
        const uint32_t ssp_flags_;
    };
    
}

#endif

