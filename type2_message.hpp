#ifndef PAL_TYPE2_MESSAGE_HPP_INCLUDED
#define PAL_TYPE2_MESSAGE_HPP_INCLUDED

#include "ntlm_message.hpp"

namespace pal {

    class type2_message : public ntlm_message {
    public:
        explicit type2_message(const std::vector<uint8_t> & buffer);
        virtual std::vector<uint8_t> as_bytes() const;
        uint32_t ssp_flags() const;
        uint64_t challenge() const;
    private:
        const std::vector<uint8_t> buffer_;
    };

}

#endif

