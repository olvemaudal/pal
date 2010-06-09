#include "tools.hpp"

#include <cstddef>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include <openssl/bio.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/md4.h>
#include <openssl/rc4.h>

std::vector<uint8_t> pal::as_bytes_from_base64_string(const std::string & str)
{
    std::vector<uint8_t> buf(str.length());
    BIO * mem = BIO_new(BIO_s_mem());
    BIO * b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_puts(mem, str.data());
    BIO_set_mem_eof_return(mem, 0);
    BIO * bio = BIO_push(b64, mem);
    (void)BIO_flush(mem);
    (void)BIO_flush(b64);
    int n = BIO_read(b64, buf.data(), buf.size());
    BIO_free_all(bio);
    buf.resize(n>0?n:0);
    return buf;
}

std::string pal::as_base64_string(const std::vector<uint8_t> & buf)
{
    std::vector<char> b64str(4+buf.size()*2); 
    BIO * mem = BIO_new(BIO_s_mem());
    BIO * b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);
    BIO * bio = BIO_push(b64, mem);
    BIO_write(bio, buf.data(), buf.size());
    (void)BIO_flush(bio);
    int n = BIO_read(mem, b64str.data(), b64str.size());
    b64str.resize(n>0?n:0);
    BIO_free_all(bio);
    return std::string(b64str.data(), b64str.size());
}

std::string pal::as_hex_dump(const std::vector<uint8_t> & buf)
{
    std::ostringstream stm;
    std::size_t len = buf.size();
    std::size_t nlines = ((len-1)/16)+1;
    for (std::size_t n=0; n!=nlines; ++n) {
        std::string asciidump;
        stm << std::setfill('0') << std::setw(4) << std::setbase(16) << 16*n << ' ';
        for (std::size_t i=0; i!=16; ++i) {
            if (i % 4 == 0) {
                stm << ' ';
                asciidump += ' ';
            }
            std::size_t idx = n*16+i;
            if ( idx<len ) {
                unsigned char ch = buf[idx];
                stm << std::setw(2) << std::setbase(16) << (int)ch << ' ';
                asciidump += isprint(ch) ? ch : '.';
            } else {
                stm << "   ";
            }
        }
        stm << asciidump << '\n';
    }
    return stm.str();
}

std::string pal::as_hex_string(const std::vector<uint8_t> & buf)
{
    static const char * hextable = "0123456789ABCDEF";
    std::vector<char> outbuf;
    outbuf.reserve(buf.size()*2);
    for (std::size_t i=0; i<buf.size(); i++) {
        outbuf.push_back(hextable[(buf[i]>>4)&0x0f]);
        outbuf.push_back(hextable[buf[i]&0x0f]);
    }
    return std::string(outbuf.data(), outbuf.size());
}

std::vector<uint8_t> pal::as_bytes_from_hex_string(
    const std::string & hex_string)
{
    std::size_t len = hex_string.length();
    std::vector<uint8_t> bytes(len);
    std::size_t at = 0;
    for (std::size_t i=0; i<len; i++) {
        char nibble = toupper(hex_string[i]);
        int val = isdigit(nibble) ? nibble - '0' : nibble - 'A' + 10;
        if( i%2 == 0 ) 
            bytes[at] = (val&0x0f)<<4;
        else 
            bytes[at++] += (val&0x0f);
    }
    bytes.resize(at);
    return bytes;
}

void pal::write_little_endian_from_uint16(uint8_t * ptr, uint16_t value)
{
    ptr[0] = (value>>0 & 0xff);
    ptr[1] = (value>>8 & 0xff);
}

void pal::write_little_endian_from_uint32(uint8_t * ptr, uint32_t value)
{
    ptr[0] = (value>>0 & 0xff);
    ptr[1] = (value>>8 & 0xff);
    ptr[2] = (value>>16 & 0xff);
    ptr[3] = (value>>24 & 0xff);
}

void pal::write_little_endian_from_uint64(uint8_t * ptr, uint64_t value)
{
    ptr[0] = (value>>0 & 0xff);
    ptr[1] = (value>>8 & 0xff);
    ptr[2] = (value>>16 & 0xff);
    ptr[3] = (value>>24 & 0xff);
    ptr[4] = (value>>32 & 0xff);
    ptr[5] = (value>>40 & 0xff);
    ptr[6] = (value>>48 & 0xff);
    ptr[7] = (value>>56 & 0xff);
}
    
uint16_t pal::read_uint16_from_little_endian(const uint8_t * ptr)
{
    return
        ((uint16_t)ptr[0]&0xff)<<0 |
        ((uint16_t)ptr[1]&0xff)<<8;
}

uint32_t pal::read_uint32_from_little_endian(const uint8_t * ptr)
{
    return
        ((uint32_t)ptr[0]&0xff)<<0 |
        ((uint32_t)ptr[1]&0xff)<<8 |
        ((uint32_t)ptr[2]&0xff)<<16 |
        ((uint32_t)ptr[3]&0xff)<<24;
}

uint64_t pal::read_uint64_from_little_endian(const uint8_t * ptr)
{
    return 
        ((uint64_t)(ptr[0]&0xff))<<0 |
        ((uint64_t)(ptr[1]&0xff))<<8 |
        ((uint64_t)(ptr[2]&0xff))<<16 |
        ((uint64_t)(ptr[3]&0xff))<<24 |
        ((uint64_t)(ptr[4]&0xff))<<32 |
        ((uint64_t)(ptr[5]&0xff))<<40 |
        ((uint64_t)(ptr[6]&0xff))<<48 |
        ((uint64_t)(ptr[7]&0xff))<<56;
}

std::vector<uint8_t> pal::md4(const std::vector<uint8_t> & bytes)
{
    std::vector<uint8_t> output(16);
    MD4(bytes.data(), bytes.size(), output.data());
    return output;
}

std::vector<uint8_t> pal::rc4(
    const std::vector<uint8_t> & key,
    const std::vector<uint8_t> & bytes)
{
    std::vector<uint8_t> cipher(bytes.size());
    RC4_KEY rc4key;
    RC4_set_key(&rc4key, key.size(), key.data());
    RC4(&rc4key, cipher.size(), bytes.data(), cipher.data());
    return cipher;
}

std::vector<uint8_t> pal::as_unicode(const std::string & str)
{
    std::vector<uint8_t> wstr;
    for (std::size_t i=0; i<str.length(); ++i) {
        wstr.push_back(str[i]);
        wstr.push_back(0x00);
    }
    return wstr;
}

std::vector<uint8_t> pal::as_bytes(const std::string & str)
{
    return std::vector<uint8_t>(str.begin(), str.end());
}

static void deskey(DES_key_schedule * ks, const unsigned char * key56)
{
    DES_cblock key;
    key[0] = key56[0];
    key[1] = ((key56[0]<<7)&0xff) | (key56[1]>>1);
    key[2] = ((key56[1]<<6)&0xff) | (key56[2]>>2);
    key[3] = ((key56[2]<<5)&0xff) | (key56[3]>>3);
    key[4] = ((key56[3]<<4)&0xff) | (key56[4]>>4);
    key[5] = ((key56[4]<<3)&0xff) | (key56[5]>>5);
    key[6] = ((key56[5]<<2)&0xff) | (key56[6]>>6);
    key[7] = ((key56[6]<<1)&0xff);
    DES_set_odd_parity(&key);
    DES_set_key(&key, ks);
}

std::vector<uint8_t> pal::des_encrypt(
    const std::vector<uint8_t> & key56,
    const std::vector<uint8_t> & bytes)
{
    std::vector<uint8_t> output(8);
    DES_key_schedule ks;
    deskey(&ks, key56.data());
    DES_ecb_encrypt((DES_cblock *)bytes.data(),
                    (DES_cblock *)output.data(), &ks, DES_ENCRYPT);
    return output;
}
