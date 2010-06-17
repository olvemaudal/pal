#ifndef NTLM_MESSAGE
#define NTLM_MESSAGE

#include <vector>

namespace pal {
    
    class ntlm_message {
    public:
        virtual std::vector<uint8_t> as_bytes() const = 0;
    };
    
}

#endif
