// demo program for the PAL library, beware lots of happy-go-lucky code here

#include "pal.hpp"

#include <arpa/inet.h>
#include <cassert>
#include <errno.h>
#include <iostream>
#include <map>
#include <memory>
#include <netdb.h>
#include <sstream>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>

static int verbose_mode = 0;

static char * my_fgets(char * s, int n, FILE * f)
{
    const char lf = 0x0a;
    const char cr = 0x0d;
    int i = 0;
    char c = 0;
    char prev_c = 0;
    int fd = fileno(f);

    while (i<n-1) {
        int rc = read(fd, &c, 1);
        if ( rc == 0 ) 
            continue;
        if ( rc != 1 )
            return 0;
        if ( (prev_c == cr) && (c == lf) ) 
            break; 
        if ( c == cr ) {
            prev_c = c;
            continue;
        }
        prev_c = s[i++] = c;
    }
    s[i++] = '\0';
    return s;
}

class http_message
{
public:
    void header_value(const std::string & name, const std::string & value) {
        header_fields_[name] = value;
    }
    std::string header_value(const std::string & name) const {
        std::map<std::string,std::string>::const_iterator i = header_fields_.find(name);
        return i->second;
    }
    void body(const std::string & data) {
        body_ = data;
    }
    std::string body() const {
        return body_;
    }
    std::string as_string() const {
        std::stringstream ss;
        ss << start_line_ << "\r\n";
        for (std::map<std::string,std::string>::const_iterator
                 i = header_fields_.begin(); i != header_fields_.end(); ++i)
            ss << i->first << ": " << i->second << "\r\n";
        ss << "\r\n";
        ss << body_;
        return ss.str();
    }
protected:
    http_message() : start_line_(), header_fields_(), body_() {}
    explicit http_message(const std::string & start_line)
        : start_line_(start_line), header_fields_(), body_() {}
    virtual ~http_message() {}
    void start_line(const std::string & line) { start_line_ = line; }
    std::string start_line() const { return start_line_; }
private:
    std::string start_line_;
    std::map<std::string,std::string> header_fields_;
    std::string body_;
};

class http_request : public http_message
{
public:
    http_request(const std::string & method, const std::string & uri) {
        if (method != "GET")
            throw std::runtime_error("unsupported method");
        start_line("GET " + uri + " HTTP/1.1");
    }
};

class http_response : public http_message
{
public:
    explicit http_response(const std::string status_line) : http_message(status_line) {
        std::stringstream ss(status_line);
        std::string version;
        ss >> version;
        if (version != "HTTP/1.1")
            throw std::runtime_error("unsupported HTTP version");
        ss >> status_code_;
    }
    int status_code() const {
        return status_code_;
    }
    std::string status_line() const {
        return start_line();
    }
private:
    int status_code_;
    std::string reason_;
};

class http_socket
{
public:
    http_socket(const std::string & host, int port) 
    : host_(host), port_(port), sock_(0) { 
        // find host
        struct hostent * addr = gethostbyname(host_.c_str());
        if (addr == NULL) {
            std::stringstream ss;
            ss << "failed to find host: " << host_
               << " h_errno=" << h_errno
               << " " << hstrerror(h_errno);
            throw std::runtime_error(ss.str());
        }

        // open socket
        int sockfd = socket(AF_INET,SOCK_STREAM,0);
        if (sockfd < 0) {
            std::stringstream ss;
            ss << "failed to create socket: "
               << "errno=" << errno
               << " " << strerror(errno);
            throw std::runtime_error(ss.str());
        }

        // connect
        struct sockaddr_in servaddr;
        char addrstr[INET_ADDRSTRLEN];
        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(port_);

        inet_ntop(AF_INET, *(addr->h_addr_list), addrstr, sizeof(addrstr));
        inet_pton(AF_INET, addrstr, &servaddr.sin_addr);

        if (verbose_mode)
            std::cout << "Connecting to " << host_ << ":" << port_ << std::endl;

        if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
            std::stringstream ss;
            ss << "failed to connect: "
               << errno << " " << strerror(errno) << std::endl;
            throw std::runtime_error(ss.str());
        }
    
        sock_ = fdopen(sockfd, "wr");
    }
    
    ~http_socket() {
        fclose(sock_);
        sock_ = 0;
    }
    
    void send(const http_request & request) {
        std::string r = request.as_string();
        ssize_t n = write(fileno(sock_), r.c_str(), r.length());
        if (verbose_mode)
            std::cout << "wrote " << n << " bytes to socket" << std::endl;
        if (n != (ssize_t)r.length()) 
            throw std::runtime_error("failed to write data to socket");
    }
    
    http_response receive() {
        char linebuf[1024]; // TODO: fix
        char * start_line = my_fgets(linebuf, sizeof(linebuf), sock_);
        http_response response(start_line);
        
        typedef std::map<std::string,std::string> field_map;
        field_map fields;
        while(1) {
            std::string header(my_fgets(linebuf, sizeof(linebuf), sock_));
            if (header == "")
                break;
            size_t pos = header.find(':');
            if (pos == std::string::npos || header.length() < pos+2) {
                std::cout << "huh?" << std::endl;
                continue;
            }
            std::string name = header.substr(0,pos);
            std::string value = header.substr(pos+2);
            fields[name] = value;
            response.header_value(name,value);
        }

        size_t content_length = atoi(response.header_value("Content-Length").c_str());

        std::vector<char> content(content_length);
        size_t read_bytes = 0;
        while (read_bytes < content_length) {
            int rc = read(fileno(sock_), content.data() + read_bytes, content.size() - read_bytes);
            if (rc == 0)
                throw std::runtime_error("unexpected end of file");
            if (rc < -1) {
                std::stringstream ss;
                ss << "failed to read content: "
                   << errno << " " << strerror(errno) << std::endl;
                throw std::runtime_error(ss.str());
            }
            read_bytes += rc;
        }

        response.body(std::string(content.begin(), content.end()));
        return response;
    }
private:
    std::string host_;
    int port_;
    FILE * sock_;
};

class http_uri
{
public:
    explicit http_uri(const std::string & uri) {
        std::string str(uri);
        
        if (str.find("http://") != 0)
            throw std::invalid_argument("invalid uri scheme (expected http://)");
        str.erase(0,7);
        
        size_t pos = str.find(':');
        if (pos == str.npos)
            throw std::invalid_argument("failed to find username");
        username_ = str.substr(0,pos);
        str.erase(0,username_.size()+1);
        
        pos = str.find('@');
        if (pos == str.npos)
            throw std::invalid_argument("failed to find password");
        password_ = str.substr(0,pos);
        str.erase(0,password_.size()+1);
        
        pos = str.find(':');
        if (pos == str.npos)
            throw std::invalid_argument("failed to find hostname");
        hostname_ = str.substr(0,pos);
        str.erase(0,hostname_.size()+1);

        pos = str.find('/');
        if (pos == str.npos)
            throw std::invalid_argument("failed to find port");
        std::string portstr = str.substr(0,pos);
        port_ = atoi(portstr.c_str());
        str.erase(0,portstr.size());

        path_ = str;
    }

    std::string username() const {
        return username_;
    }

    std::string password() const {
        return password_;
    }

    std::string hostname() const {
        return hostname_;
    }

    int port() const {
        return port_;
    }

    std::string path() const {
        return path_;
    }

private:
    std::string username_;
    std::string password_;
    std::string hostname_;
    int port_;
    std::string path_;
};

void print_usage(std::ostream & out)
{
    out << "examples:\n"
        << "  httpget http://Administrator:super@192.168.56.101:80/secret.txt\n" 
        << "  httpget -v http://Administrator:super@192.168.56.101:80/public.txt"
        << std::endl;
}

int main(int argc, char * argv[])
{
    // parse command line
    if (argc < 2) {
        print_usage(std::cout);
        return 0;
    }
    int argi = 1;
    if (argc == 3 && std::string(argv[1]) == "-v" ) {
        verbose_mode = 1;
        ++argi;
    }
    if (argi+1 != argc) {
        std::cout << "failed to parse command line" << std::endl;
        return -1;
    }
    
    // parse the uri and open http socket
    http_uri uri(argv[argi]);
    http_socket socket(uri.hostname(),uri.port());

    // send initial http request
    http_request request("GET", uri.path());
    request.header_value("Host", uri.hostname().c_str());
    request.header_value("Connection", "keep-alive");
    socket.send(request);
    http_response response = socket.receive();

    // if "200 OK" then no authentication needed, we're done
    if (response.status_code() == 200) {
        std::cout << response.body() << std::endl;
        return 0;
    }

    // if it is not 401 + NTLM authentication that is requested then give up
    if (response.status_code() != 401) {
        std::cout << response.status_line() << std::endl;
        return -1;
    }
    if (response.header_value("WWW-Authenticate") != "NTLM") { // TODO: fix this, might be several
        std::cout << "unknown authentication requested" << std::endl;
        return -1;
    }

    // create initial NTLM request
    std::auto_ptr<pal::ntlm_message> ntlm_request_msg (pal::create_ntlm_request());
    std::string ntlm_request = pal::as_base64_string(ntlm_request_msg->as_bytes());

    // send a new request, expect another 401 containing an NTLM challenge
    request.header_value("Authorization", "NTLM " + ntlm_request);
    socket.send(request);
    response = socket.receive();

    
    // assume a 401, extract the NTLM challenge and solve it
    if (response.status_code() != 401) {
        std::cout << response.status_line() << std::endl;
        return -1;
    }
    std::string auth_str = response.header_value("WWW-Authenticate");
    if (auth_str.length() < 10 || auth_str.substr(0,4) != "NTLM") {
        std::cout << "unexpected authentication challenge: " << auth_str << std::endl;
        return -1;
    }
    std::string ntlm_challenge_str = auth_str.substr(5);
    std::auto_ptr<pal::ntlm_message> ntlm_challenge_msg (
        pal::create_ntlm_challenge(pal::as_bytes_from_base64_string(ntlm_challenge_str)));
    std::auto_ptr<pal::ntlm_message> ntlm_response_msg(
        pal::create_ntlm_response(uri.username(), uri.password(), *ntlm_challenge_msg));
    std::vector<uint8_t> response_buf = ntlm_response_msg->as_bytes();
    std::string ntlm_response = pal::as_base64_string(response_buf);

    // challenge solve (hopefully), send the NTLM response and get the data
    request.header_value("Authorization", "NTLM " + ntlm_response);
    socket.send(request);
    response = socket.receive();
    if (response.status_code() != 200) {
        std::cout << response.status_line() << std::endl;
        std::cout << "Sorry, failed to get data" << std::endl;
        return -1;
    }

    // we have the content, here it is
    std::cout << response.body() << std::endl;
}
