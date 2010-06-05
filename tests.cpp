#include "pal_internal.hpp"

#include "tools.hpp"
#include "type1_message.hpp"
#include "type2_message.hpp"
#include "type3_message.hpp"

#include <iostream>
#include <assert.h>

#define FAIL_TEST(x) assert(0 && (x))
#define ASSERT_TEST(x) assert(x)
#define IGNORE_TEST(x) assert(1 || (x))
#define RUN_TEST(x) std::cout << #x << std::endl; x();

static void test_byte64_encoding_and_decoding()
{
    uint8_t b[] = {1,2,3,4,5,6};
    std::vector<uint8_t> bytes(b, b + sizeof b);
    std::string b64str = pal::as_base64_string(bytes);
    ASSERT_TEST( "AQIDBAUG" == b64str );
    bytes.pop_back();
    b64str = pal::as_base64_string(bytes);
    ASSERT_TEST( "AQIDBAU=" == b64str );
    bytes.pop_back();
    b64str = pal::as_base64_string(bytes);
    ASSERT_TEST( "AQIDBA==" == b64str );
    bytes.pop_back();
    b64str = pal::as_base64_string(bytes);
    ASSERT_TEST( "AQID" == b64str );
    bytes.pop_back();
    bytes.pop_back();
    b64str = pal::as_base64_string(bytes);
    ASSERT_TEST( "AQ==" == b64str );
    bytes.pop_back();
    b64str = pal::as_base64_string(bytes);
    
    std::vector<uint8_t> bytes2 = pal::as_bytes_from_base64_string("");
    ASSERT_TEST( std::equal(bytes2.begin(), bytes2.end(), bytes.begin()) );
    bytes.push_back(1);
    bytes.push_back(2);
    bytes.push_back(3);
    bytes2 = pal::as_bytes_from_base64_string("AQID");
    ASSERT_TEST( std::equal(bytes2.begin(), bytes2.end(), bytes.begin()) );
    bytes2.push_back(4);
    bytes2 = pal::as_bytes_from_base64_string("AQIDBA==");
    ASSERT_TEST( std::equal(bytes2.begin(), bytes2.end(), bytes.begin()) );
    bytes2.push_back(5);
    bytes2.push_back(6);
    bytes2 = pal::as_bytes_from_base64_string("AQIDBAUG");
    ASSERT_TEST( std::equal(bytes2.begin(), bytes2.end(), bytes.begin()) );
}

static void test_converting_between_hex_string_and_bytes()
{
    std::vector<uint8_t> buf = pal::as_bytes_from_hex_string("CAFE0142");
    ASSERT_TEST(buf.size() == 4);
    ASSERT_TEST(buf[0] == 0xCA && buf[1] == 0xFE &&
                buf[2] == 0x01 && buf[3] == 0x42);
    std::string str = pal::as_hex_string(buf);
    ASSERT_TEST(str == "CAFE0142");
    buf = pal::as_bytes_from_hex_string("");
    ASSERT_TEST(buf.size() == 0);
    str = pal::as_hex_string(buf);
    ASSERT_TEST(str == "");
}

static void test_converting_string_to_unicode()
{
    std::vector<uint8_t> ustr = pal::as_unicode("Hello");
    uint8_t expected[] = {'H',0,'e',0,'l',0,'l',0,'o',0};
    ASSERT_TEST( std::equal(ustr.begin(), ustr.end(), expected) );
    ASSERT_TEST( ustr.size() == 10 );
    ustr = pal::as_unicode("");
    ASSERT_TEST( ustr.size() == 0 );
}

static void test_creating_nt_response()
{
    std::vector<uint8_t> pwdhash = pal::create_password_hash("secret");
    std::vector<uint8_t> expected = pal::as_bytes_from_hex_string("878D8014606CDA29677A44EFA1353FC7");
    ASSERT_TEST(pwdhash.size() == 16);
    ASSERT_TEST(pwdhash.size() == expected.size());
    ASSERT_TEST(std::equal(pwdhash.begin(), pwdhash.end(), expected.begin()));
}

static void test_creating_encrypted_session_key()
{
    std::vector<uint8_t> ph = pal::create_password_hash("secret");
    std::vector<uint8_t> sk = pal::as_bytes_from_hex_string("00112233445566778899AABBCCDDEEFF");
    std::vector<uint8_t> esk = pal::create_encrypted_session_key(ph,sk);
    std::vector<uint8_t> expected = pal::as_bytes_from_hex_string("F108FD16C6A48F619EDC61EC9EEC32F9");
    ASSERT_TEST(esk.size() == expected.size());
    ASSERT_TEST(std::equal(esk.begin(), esk.end(), expected.begin()));
}

static void test_creating_md4_digest()
{
    std::vector<uint8_t> input = pal::as_bytes_from_hex_string("8899AABBCCDDEEFF0011223344556677");
    std::vector<uint8_t> output = pal::md4(input);
    std::vector<uint8_t> expected = pal::as_bytes_from_hex_string("5C0EC35E7A167E8D218C3CE168888723");
    ASSERT_TEST(expected.size() == output.size());
    ASSERT_TEST(std::equal(expected.begin(), expected.end(), output.begin()));
}
    
static void test_encoding_with_rc4()
{
    std::vector<uint8_t> text = pal::as_bytes_from_hex_string("8899AABBCCDDEEFF0011223344556677");
    std::vector<uint8_t> key = pal::as_bytes_from_hex_string("00112233445566778899AABBCCDDEEFF");
    std::vector<uint8_t> cipher = pal::rc4(key,text);
    std::vector<uint8_t> expected = pal::as_bytes_from_hex_string("0DC206EC5EFA8F7AF8489B08D1101BE3");
    ASSERT_TEST(expected.size() == cipher.size());
    ASSERT_TEST(std::equal(expected.begin(), expected.end(), cipher.begin()));
}

static void test_calculating_lm_response()
{
    uint64_t challenge = 0xCAFEBABEDEADBEEF;
    std::vector<uint8_t> lmr = pal::calculate_lm_response("secret", challenge);
    ASSERT_TEST( lmr.size() == 24 );
    std::vector<uint8_t> expected = pal::as_bytes_from_hex_string("86730DE4EE77DB37308780F2801F7097CE876C4F37A90E18");
    ASSERT_TEST( lmr.size() == expected.size() );
    ASSERT_TEST( std::equal(expected.begin(), expected.end(), lmr.begin()) );
}

static void test_decoding_of_type2_message()
{
    char const * data = "TlRMTVNTUAACAAAAAAAAADgAAADzgpjiavm/AUnPdy4AAAAAAAAAAIYAhgA4AAAABQLODgAAAA8CABAAQgBJAFIARABMAEEATgBEAAEACgBZAFUAQwBDAEEABAAYAGIAaQByAGQAbABhAG4AZAAuAGkAbgB0AAMAJAB5AHUAYwBjAGEALgBiAGkAcgBkAGwAYQBuAGQALgBpAG4AdAAFABgAYgBpAHIAZABsAGEAbgBkAC4AaQBuAHQAAAAAAA==";
    pal::type2_message t2(pal::as_bytes_from_base64_string(data));
    ASSERT_TEST( t2.challenge() == (uint64_t)0x2e77cf4901bff96a );
    ASSERT_TEST( t2.ssp_flags() == (uint32_t)0xe29882f3 );
}

static void test_request_challenge_response_sequence()
{
    std::auto_ptr<pal::ntlm_message> request(pal::create_ntlm_request());
    std::string request_str = pal::as_base64_string(request->as_bytes());
    std::string expected_request_str = "TlRMTVNTUAABAAAAAgIAAA==";
    ASSERT_TEST( expected_request_str == request_str );

    std::string challenge_str = "TlRMTVNTUAACAAAAAAAAADgAAAACAgAC6d1dZnbXIl4AAAAAAAAAAAAAAAA4AAAABQLODgAAAA8=";
    std::auto_ptr<pal::ntlm_message> challenge(pal::create_ntlm_challenge(pal::as_bytes_from_base64_string(challenge_str)));

    std::string username = "Administrator";
    std::string password = "super";
    std::auto_ptr<pal::ntlm_message> response(pal::create_ntlm_response(username,password,*challenge));
    std::string response_str = pal::as_base64_string(response->as_bytes());
    std::string expected_response_str = "TlRMTVNTUAADAAAAGAAYAEAAAAAYABgAWAAAAAAAAABwAAAADQANAHAAAAAAAAAAfQAAABAAEAB9AAAAAAIAABhBdYkMBBP/sMvC3ZmAZ3B8nlmh5E4NZGg5LnmDj4edn8Gk3G/m/6L8DA9GNbvV3EFkbWluaXN0cmF0b3IAAAAAAAAAAAAAAAAAAAAA";

    //std::cout << pal::as_hex_dump(response->as_bytes()) << std::endl;
    //std::cout << pal::as_hex_dump(pal::as_bytes_from_base64_string(expected_response_str)) << std::endl;
    ASSERT_TEST( expected_response_str == response_str );
}

int main()
{
    RUN_TEST(test_byte64_encoding_and_decoding);
    RUN_TEST(test_converting_between_hex_string_and_bytes);
    RUN_TEST(test_converting_string_to_unicode);
    RUN_TEST(test_creating_nt_response);
    RUN_TEST(test_creating_encrypted_session_key);
    RUN_TEST(test_creating_md4_digest);
    RUN_TEST(test_encoding_with_rc4);
    RUN_TEST(test_calculating_lm_response);
    RUN_TEST(test_decoding_of_type2_message);
    RUN_TEST(test_request_challenge_response_sequence);
    std::cerr << "tests OK" << std::endl;
}
