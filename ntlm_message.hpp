#ifndef NTML
#define NTML

#include <vector>

namespace pal {
    
    class ntlm_message {
    public:
        ~ntlm_message() {}
        virtual std::vector<uint8_t> as_bytes() const = 0;
    };
    
}

#endif // NTLM
