#ifndef _DNS_LOOKUP_H_
#define _DNS_LOOKUP_H_

#include <string>
#include <vector>
using namespace std;

#define DNS_TYPE_A	   1
// #define DNS_TYPE_NS	   2
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_SOA   6
// #define DNS_TYPE_PTR   12
// #define DNS_TYPE_MX	   15
// #define DNS_TYPE_TXT   16
#define DNS_TYPE_AAAA  28
#define DNS_TYPE_CAA   257

typedef struct{
    uint16_t type;
    uint32_t ttl;
    vector<string> value;
}DnsRecord;

class DnsLookup
{
public:
    DnsLookup(const char *dns_server = "8.8.8.8");
    DnsLookup(const vector<string> &dns_servers);
    ~DnsLookup();

    // return 0: success, other: error
    int Lookup(const char *host, int dns_type);
    const vector<DnsRecord> *get_dns_records() const;

private:
    int dns_lookup_tcp(const char *host, int dns_type);
    int dns_lookup_udp(const char *host, int dns_type);

    static void tcp_recv_dns_response(int sockfd, short events, void* arg);
    static void udp_recv_dns_response(int sockfd, short events, void* arg);
    static void decode_dns_response(unsigned char *recvBuff, size_t numbytes, vector<DnsRecord> *records);

    int send_dns_package(int dnsType, int sockfd, struct sockaddr *to, const char *hostname, int tcp);
    int generate_dns_request(int dnsType, const char *hostname, unsigned char *sendBuff);


private:

    vector<string> dns_servers_;
    vector<DnsRecord> dns_records_; 
};

#endif //_DNS_LOOKUP_H_