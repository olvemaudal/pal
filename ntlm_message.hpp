#ifndef PAL_NTLM_MESSAGE_HPP
#define PAL_NTLM_MESSAGE_HPP

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

