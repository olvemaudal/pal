#include "pal.hpp"
#include "pal_internal.hpp"

#include "ntlm_ssp_flags.hpp"
#include "tools.hpp"
#include "type1_message.hpp"
#include "type2_message.hpp"
#include "type3_message.hpp"

#include <cassert>
#include <stdexcept>
#include <string.h>

std::vector<uint8_t> pal::create_password_hash(const std::string & password)
{
    // TODO: has password a max len?
    std::vector<uint8_t> password_hash = pal::md4(pal::as_unicode(password));
    assert( password_hash.size() == 16 ); // TODO: fix
    return password_hash;
}

std::vector<uint8_t> pal::create_nt_response(
    const std::vector<uint8_t> & password_hash,
    uint64_t challenge)
{
    if (password_hash.size() != 16)
        throw std::invalid_argument("invalid size of password_hash");

    unsigned char p21[21];
    memset(p21, 0, sizeof p21);
    memcpy(p21, password_hash.data(), 16);

    unsigned char challenge_bytes[8];
    pal::write_little_endian_from_uint64(challenge_bytes, challenge);

    std::vector<uint8_t> cb(challenge_bytes, challenge_bytes + sizeof challenge_bytes);
    std::vector<uint8_t> p24chunk1 = pal::des_encrypt(std::vector<uint8_t>(p21+0, p21+7), cb);
    std::vector<uint8_t> p24chunk2 = pal::des_encrypt(std::vector<uint8_t>(p21+7, p21+14), cb);
    std::vector<uint8_t> p24chunk3 = pal::des_encrypt(std::vector<uint8_t>(p21+14, p21+21), cb);
    std::vector<uint8_t> r;
    r.reserve(24);
    r.insert(r.end(), p24chunk1.begin(), p24chunk1.end());
    r.insert(r.end(), p24chunk2.begin(), p24chunk2.end());
    r.insert(r.end(), p24chunk3.begin(), p24chunk3.end());
    assert( r.size() == 24 );

    return r;
}

std::vector<uint8_t> pal::create_session_key()
{
    // in a more sophisticated implementation this should be a random sequence
    return std::vector<uint8_t>(16, 0);
}

std::vector<uint8_t> pal::create_encrypted_session_key(
    const std::vector<uint8_t> & password_hash,
    const std::vector<uint8_t> & session_key)
{
    return pal::rc4(pal::md4(password_hash), session_key);
}

std::vector<uint8_t> pal::calculate_lm_response(
    const std::string & password,
    uint64_t challenge)
{
    // create a byte buffer out of challenge
    std::vector<uint8_t> challenge_bytes(8);
    pal::write_little_endian_from_uint64(challenge_bytes.data(), challenge);
    
    std::vector<uint8_t> upcase_and_padded_pwd(14,0);
    
    // convert password to uppercase and pad with 0x00
    for (size_t at = 0; at != password.length() && at < upcase_and_padded_pwd.size(); ++at) 
        upcase_and_padded_pwd[at] = toupper(password[at]);

    // split into two 7-byte halves
    std::vector<uint8_t> left_key(upcase_and_padded_pwd.begin(), upcase_and_padded_pwd.begin()+7);
    std::vector<uint8_t> right_key(upcase_and_padded_pwd.begin()+7, upcase_and_padded_pwd.end());
    assert(left_key.size() == 7 && right_key.size() == 7);

    // DES encrypt the halves
    const std::string our_secret_str = "KGS!@#$%";
    std::vector<uint8_t> our_secret(our_secret_str.begin(), our_secret_str.end());
    std::vector<uint8_t> crypted_with_left_key = pal::des_encrypt(left_key, our_secret);
    std::vector<uint8_t> crypted_with_right_key = pal::des_encrypt(right_key, our_secret);

    // create 16-byte LM hash and pad it to 21-bytes
    std::vector<uint8_t> lm_hash;
    lm_hash.insert(lm_hash.end(), crypted_with_left_key.begin(), crypted_with_left_key.end());
    lm_hash.insert(lm_hash.end(), crypted_with_right_key.begin(), crypted_with_right_key.end());
    lm_hash.insert(lm_hash.end(), 5, 0x00);

    // split into three 7 byte des keys
    std::vector<uint8_t> key1(&lm_hash[0], &lm_hash[7]);
    std::vector<uint8_t> key2(&lm_hash[7], &lm_hash[14]);
    std::vector<uint8_t> key3(&lm_hash[14], &lm_hash[21]);
    
    // use the keys to encrypt the challenge
    std::vector<uint8_t> crypted_with_key1 = pal::des_encrypt(key1, challenge_bytes);
    std::vector<uint8_t> crypted_with_key2 = pal::des_encrypt(key2, challenge_bytes);
    std::vector<uint8_t> crypted_with_key3 = pal::des_encrypt(key3, challenge_bytes);

    // concatenate the crypted results
    std::vector<uint8_t> response;
    response.reserve(24);
    response.insert(response.end(), crypted_with_key1.begin(), crypted_with_key1.end());
    response.insert(response.end(), crypted_with_key2.begin(), crypted_with_key2.end());
    response.insert(response.end(), crypted_with_key3.begin(), crypted_with_key3.end());
    assert( response.size() == 24 );

    return response;
}

pal::ntlm_message * pal::create_ntlm_request()
{
    uint32_t ssp_flags = NTLM_SSP_NEGOTIATE_OEM | NTLM_SSP_NEGOTIATE_NTLM;
    
    return new type1_message(ssp_flags);
}

pal::ntlm_message * pal::create_ntlm_challenge(
    const std::vector<uint8_t> & challenge_as_bytes)
{
    return new type2_message(challenge_as_bytes);
}
    
pal::ntlm_message * pal::create_ntlm_response(
    const std::string & username,
    const std::string & password,
    const pal::ntlm_message & ntlm_msg)
{
    std::vector<uint8_t> password_hash = create_password_hash(password);
    assert(password_hash.size() == 16);
    std::vector<uint8_t> session_key = create_session_key();
    assert(session_key.size() == 16);
    std::vector<uint8_t> encrypted_session_key =
        create_encrypted_session_key(password_hash, session_key);
    assert(encrypted_session_key.size() == 16);
    
    pal::type2_message t2msg(ntlm_msg.as_bytes()); 
    const uint64_t challenge = t2msg.challenge();
    
    std::vector<uint8_t> lm_response =
        calculate_lm_response(password, challenge);
    assert(lm_response.size() == 24);
    std::vector<uint8_t> nt_response =
        create_nt_response(password_hash, challenge);
    assert(nt_response.size() == 24);

    return new type3_message(lm_response, nt_response, username,
                             NTLM_SSP_NEGOTIATE_NTLM);
}

