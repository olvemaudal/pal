#ifndef PAL_NTLM_MESSAGE_HPP_INCLUDED
#define PAL_NTLM_MESSAGE_HPP_INCLUDED

#include <stdint.h>
#include <vector>

namespace pal {
    
    class ntlm_message {
    public:
        virtual ~ntlm_message() {}
        virtual std::vector<uint8_t> as_bytes() const = 0;
    };
    
}

#endif

