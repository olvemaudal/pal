#ifndef PAL_TYPE2_MESSAGE_HPP_INCLUDED
#define PAL_TYPE2_MESSAGE_HPP_INCLUDED

#include "ntlm_message.hpp"

using namespace std;

namespace pal {

    class type2_message : public ntlm_message {
    public:
        explicit type2_message(vector<uint8_t> buffer);
        virtual vector<uint8_t> as_bytes() const;
        uint32_t ssp_flags();
        uint64_t challenge();
    private:
        const vector<uint8_t> buffer_;
    };

}

#endif

