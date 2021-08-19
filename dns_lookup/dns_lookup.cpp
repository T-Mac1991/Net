/************************************************************************
File name - dns_lookup.cpp
Purpose - An dns client, which accepts  domain name from keyboard and \
            print it's ipv4/ipv6/caa.
            Reactor framework (libevent) is used.
To compile - gcc -o dns_lookup dns_lookup.cpp -levent -g
************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <event.h>
#include <event2/util.h> 

#include "dns_lookup.h"


#define BUFSIZE 512
#define MAXSERVERNAME 100

#define DNS_PORT 53

/* 
**DNS报文首部
*/
typedef struct //DNS message header
{
    unsigned short id;         //会话标识
    unsigned short flags;
    unsigned short questNum;   // 表示查询问题区域节的数量 
    unsigned short answerNum;  // 表示回答区域的数量
    unsigned short authorNum;  // 表示授权区域的数量
    unsigned short additionNum;// 表示附加区域的数量
} DNSHDR, *pDNSHDR;

typedef struct //DNS message request recored
{
    unsigned short type;
    unsigned short queryclass;
} QUERYHDR, *pQUERYHDR;

#pragma pack(push, 1)//保存对齐状态，设定为1字节对齐
typedef struct //DNS message response recored
{
    unsigned short type;
    unsigned short classes;
    unsigned int ttl;
    unsigned short length;
} RESPONSEHDR, *pRESPONSEHDR;
#pragma pack(pop) //恢复对齐状态

typedef struct _tagEventParam {
    struct event_base* base = NULL;
    vector<DnsRecord> *dns_records = NULL;
}EventParam;


//节选自www.diggui.com
static const char DnsHosts[][32] = {
    // Google Public DNS
    "8.8.8.8",             
    //"8.8.4.4",              
    //"2001:4860:4860::8888", 
    //"2001:4860:4860::8844", 

    // Cloudflare
    "1.1.1.1",              
    //"1.0.0.1",              
    //"2606:4700:4700::1111",              
    //"2606:4700:4700::1001",  

    //Quad9
    "9.9.9.9",
    "149.112.112.112",
    //"2620:fe::fe",
    //"2620:fe::9",

    //OpenDNS
    "208.67.222.222",
    //"208.67.220.220",
    //"2620:0:ccc::2",
    //"2620:0:ccd::2",

    //Level3
    "209.244.0.3",
    //"209.244.0.4",
    "4.2.2.1",
    // "4.2.2.2",
    // "4.2.2.3",
    // "4.2.2.4",
    // "4.2.2.5",
    // "4.2.2.6",

    //114DNS
    "114.114.114.114",
    //"114.114.115.115"
};

DnsLookup::DnsLookup(const char *dns_server /*= "8.8.8.8"*/) 
{
    dns_servers_.emplace_back(dns_server);
}

DnsLookup::DnsLookup(const vector<string> &dns_servers) : dns_servers_(dns_servers)
{
}

DnsLookup::~DnsLookup()
{
}


int DnsLookup::Lookup(const char *host, int dns_type)
{
    dns_records_.clear();

    if (strchr(host, '.') == NULL)
        return -1;

    char *hostname = (char*)host;
    if (strncasecmp(hostname, "www.", 4) == 0)
        hostname += 4;

    int ret = dns_lookup_udp(hostname, dns_type);
    if (ret < 0) {
        dns_lookup_tcp(hostname, dns_type);
    }
    return ret;
}

const vector<DnsRecord> *DnsLookup::get_dns_records() const 
{
    return &dns_records_;
}

int DnsLookup::dns_lookup_tcp(const char *host, int dns_type)
{
    int sd = -1, ret = -1;
    //DNS address from /etc/resolv.conf

    struct event_base* base = NULL;
    struct sockaddr_in s_addr;
    std::vector<int> sockfds(dns_servers_.size());
    //for (int i = 0; i < sizeof(DnsHosts) / sizeof(DnsHosts[0]); i++)
    for (auto &it : dns_servers_)
    {
        sd = socket(AF_INET, SOCK_STREAM, 0);  //use TCP
        if (sd < 0)
        {
            printf("socket failed: %d", errno);
            continue;
        }
        sockfds.emplace_back(sd);

        memset(&s_addr, 0, sizeof(s_addr));
        s_addr.sin_family = AF_INET;
        s_addr.sin_port = htons(DNS_PORT);    //PORT NO
        s_addr.sin_addr.s_addr = inet_addr(it.c_str()); //ADDRESS

        if (connect(sd, (const sockaddr*)&s_addr, sizeof(struct sockaddr_in)) != 0){
            printf("Connect failed: %d", errno);
            continue;
        }

        ret = send_dns_package(dns_type, sd, (struct sockaddr *)&s_addr, host, 1);
        if (ret < 0)
        {
            printf("send_dns_package failed: %d", errno);
            continue;
        }

        if (!base)
            base = event_base_new();

        //when sd has data to read
        EventParam params;
        params.base = base;
        params.dns_records = &dns_records_;        
        struct event *ev_sockfd = event_new(base, sd,  
                                            EV_READ | EV_PERSIST | EV_ET,  
                                            tcp_recv_dns_response, &params);
        event_add(ev_sockfd, NULL);
    }

    if (base)
        event_base_dispatch(base);  

    //printf("finished \n"); 
    for (auto &it : sockfds)
        close(it);

    return 0;
}


int DnsLookup::dns_lookup_udp(const char *host, int dns_type)
{
    int sd, ret;
    //DNS address from /etc/resolv.conf
    sd = socket(AF_INET, SOCK_DGRAM, 0);  //use UDP
    if (sd < 0)
    {
        printf("socket failed: %d", errno);
        return -1;
    }

    struct event_base* base = NULL;
    struct sockaddr_in s_addr;
    //for (int i = 0; i < sizeof(DnsHosts) / sizeof(DnsHosts[0]); i++)
    for (auto &it : dns_servers_)
    {
        memset(&s_addr, 0, sizeof(s_addr));
        s_addr.sin_family = AF_INET;
        s_addr.sin_port = htons(DNS_PORT);    //PORT NO
        s_addr.sin_addr.s_addr = inet_addr(it.c_str()); //ADDRESS

        ret = send_dns_package(dns_type, sd, (struct sockaddr *)&s_addr, host, 0);
        if (ret < 0)
        {
            printf("send_dns_package failed");
            close(sd);
            return -1;
        }
    }

    base = event_base_new();
    EventParam params;
    params.base = base;
    params.dns_records = &dns_records_;
    //when sd has data to read
    struct event *ev_sockfd = event_new(base, sd,  
                                        EV_READ | EV_PERSIST,  
                                        udp_recv_dns_response, &params);
    event_add(ev_sockfd, NULL);
    
    event_base_dispatch(base);  
    event_base_free(base);
    printf("finished \n"); 
    close(sd);
    return 0;
}

int DnsLookup::send_dns_package(int dnsType, int sockfd, struct sockaddr *to, const char *hostname, int tcp)
{
    int ret = 0;
    unsigned short reqlen = 0;
    unsigned char sendBuff[BUFSIZE] = {0};

    /*Prepapre DNS request message*/
    reqlen = generate_dns_request(dnsType, hostname, sendBuff);
    if (reqlen <= 0)
    {
        perror("Generate dns request error\n");
        return -1;
    }

    if (tcp == 1)
    {
		unsigned short len = htons(reqlen);
        ret = send(sockfd, &len, sizeof(unsigned short), 0);
        if (ret < 0)
        {
            printf("Error in sending data: %d", errno);
            return -1;
        }

        ret = send(sockfd, sendBuff, reqlen, 0);
    }
    else
    {
        /*Sending the read data over socket*/
        ret = sendto(sockfd, sendBuff, reqlen, 0, to, sizeof(struct sockaddr_in));
    }

    if (ret < 0)
    {
        printf("Error in sending data: %d\n", errno);
        return -1;
    }

    printf("Data Sent To Server, please waiting...\n");
    return 0;
}

static int tcp_recv(int fd, unsigned char* recvBuf, size_t* recvlen)
{
	int result = 0;

	do
	{
		if (fd == 0 ||
			recvBuf == NULL ||
			recvlen == NULL ||
			*recvlen == 0)
		{
			break;
		}

        int sum = 0;
		while (1)
		{
			int len = recv(fd, recvBuf + sum, *recvlen - sum, 0);
			if (len <= 0)
			{
				break;
			}
			sum += len;
		}

		*recvlen = sum;
		result = 1;
	} while (0);

	return result;
}

void DnsLookup::udp_recv_dns_response(int sockfd, short, void* arg)  {
    EventParam *param = (EventParam*)arg;
    if (!param || !param->base || !param->dns_records)
        return;
    socklen_t structlen;
    struct sockaddr_in s_addr;
    unsigned char recvbuf[BUFSIZE] = {0};
    size_t numbytes = 0;
    structlen = sizeof(s_addr);
    
    do {
        numbytes = recvfrom(sockfd, recvbuf, BUFSIZE, 0, 
            (struct sockaddr *)&s_addr, &structlen);
        printf("\n\nData Received from server: %s:%d \n", inet_ntoa(s_addr.sin_addr), ntohs(s_addr.sin_port));

        if (numbytes <= 0)
        {
            printf("Error in receiving data: %d", errno);
            return;
        }
    } while (0);

    /*decode DNS Response*/
    decode_dns_response(recvbuf, numbytes, param->dns_records);

    event_base_loopbreak(param->base);
    return ;
}


void DnsLookup::tcp_recv_dns_response(int sockfd, short, void* arg)  {
    EventParam *param = (EventParam*)arg;
    if (!param || !param->base || !param->dns_records)
        return;
    unsigned char recvbuf[BUFSIZE] = {0};
    size_t numbytes = 0;
    unsigned char *pRecvbuf = NULL;

    do 
    {
        // 获取数据长度
        unsigned short recvSize = 0;
        size_t recvlen = sizeof(recvSize);
        if (tcp_recv(sockfd, (unsigned char*)&recvSize, &recvlen) == 0 || recvlen == 0)
        {
            break;
        }

        // 获取数据
        recvlen = ntohs(recvSize);
        if (recvlen > BUFSIZE)
        {
            pRecvbuf = (unsigned char*)malloc(recvlen);
            if (pRecvbuf == NULL)
            {
                break;
            }
            memset(pRecvbuf, 0, recvlen);
            if (!tcp_recv(sockfd, pRecvbuf, &numbytes))
            {
                break;
            }
        }
        else
        {
            numbytes = BUFSIZE;
            if (!tcp_recv(sockfd, recvbuf, &numbytes))
            {
                break;
            }
        }

        if (numbytes <= 0)
        {
            printf("Error in receiving data: %d", errno);
            break;
        }

    } while (0);

    /*decode DNS Response*/
    decode_dns_response(pRecvbuf ? pRecvbuf : recvbuf, numbytes, param->dns_records);
    if (pRecvbuf)
        free(pRecvbuf);

    event_base_loopbreak(param->base);
    return ;
}

int DnsLookup::generate_dns_request(int dnsType, const char *hostname, unsigned char *sendBuff)
{
    if (!strcmp(hostname, "exit"))
    {
        return -1; //input exit finish
    }
    else //正常的DNS查询请求
    {
        DNSHDR dnsHdr; 
        memset(&dnsHdr, 0, sizeof(dnsHdr));

        QUERYHDR queryHdr;
        memset(&queryHdr, 0, sizeof(queryHdr));

        int iSendByte = 0;
        dnsHdr.id = htons(0x0000);        //"标识"字段设置为0
        dnsHdr.flags = htons(0x0100);     //"标志"字段设置为0x0100, 即RD位为1期望递归查询
        dnsHdr.questNum = htons(0x0001);  //1个查询记录
        dnsHdr.answerNum = htons(0x0000); //没有回答记录和其它的记录
        dnsHdr.authorNum = htons(0x0000);
        dnsHdr.additionNum = htons(0x0000);
        //将生成的DNS查询报文首部复制到sendBuff中
        memcpy(sendBuff, &dnsHdr, sizeof(DNSHDR));
        iSendByte += sizeof(DNSHDR); //记录当前的数据量

        //对域名字符串进行解析并且进行形式的变换
        char transHostname[256] = {0};
        strcpy(transHostname + 1, hostname); //第一个字符无实际意义, 从第二个开始
        char *pTrace = transHostname + 1;
        char *pNumber = transHostname;

        int iStrLen = strlen(hostname) + 2; //解析完之后会多出2个字符
        unsigned char iCharNum = 0;

        //报文中字符域名需要调整，如"baidu.com\0"需要调整为"5baidu3com0"
        while (*pTrace != '\0')
        {
            if (*pTrace == '.')
            {
                *pNumber = iCharNum;
                pNumber = pTrace;
                iCharNum = 0;
            }
            else
            {
                iCharNum++;
            }
            pTrace++;
        }
        *pNumber = iCharNum;

        memcpy(sendBuff + sizeof(DNSHDR), transHostname, iStrLen);
        iSendByte += iStrLen; 

        //在域名字段之后填入“查询类型”和“查询类”
        queryHdr.type = htons(dnsType);  //DNS_TYPE_CAA
        queryHdr.queryclass = htons(0x0001);
        memcpy(sendBuff + sizeof(DNSHDR) + iStrLen, &queryHdr, sizeof(QUERYHDR));

        iSendByte += sizeof(QUERYHDR); // 累加得到的字节数
        return iSendByte;              //返回最终得到的字节数
    }
}

static int get_offset(unsigned char *p)
{
    //偏移量
    if ((p[0] & 0xC0) == 0xC0)
    {
        //eg: 偏移量0xC0 0C: 1100 0000 0000 1100 最开始的两个bit为1，后14bit表示偏移量
        return (int)((p[0] & 0x3F) << 8 | p[1]);
    }
    return 0;
}


static char *trans_domain(unsigned char*& p, int nTotalLen, unsigned char* recvBuf, size_t numbytes, char domain[256])
{
    int i = 0;
    int len = 0;
    domain[0] = 0;
    int totlalen = nTotalLen > 256 ? 256 : nTotalLen;
    while (*p)
    {
        //eg: 偏移量0xC0 0C: 1100 0000 0000 1100 最开始的两个bit为1，后14bit表示偏移量
        if (recvBuf && (p[0] & 0xC0) == 0xC0)
        {
            int offset = get_offset(p);
            if (offset > (int)numbytes)
                return domain;

            char subDomain[256] = {0};
            unsigned char *tmp = recvBuf + offset;
            strcat(&domain[i], trans_domain(tmp, -1, recvBuf, numbytes, subDomain));
            p += 2;
            break;
        }

        len = *p++;

        if (nTotalLen != -1)
        {
            totlalen -= len;
        }

        while (len-- > 0)
        {
            domain[i++] = *p++;
        }

        len = *p;
        if (len == 0)
        {
            domain[i] = 0;
            p++;
            break;
        }  

        domain[i++] = '.';

        if (nTotalLen != -1 && totlalen < 0)
        {
            return domain;
        }  
    }
    return domain;
}

void DnsLookup::decode_dns_response(unsigned char *recvBuff, size_t numbytes, vector<DnsRecord> *records)
{
    if (recvBuff == NULL)
    {
        perror("No messge received\n");
        return;
    }

    pDNSHDR pDnsHdr = (pDNSHDR)recvBuff;
    //保存所有附加信息
    int iFlags, /*iQueryNum,*/ iRespNum, iAuthRespNum/*, iAdditionNum*/;
    iFlags = ntohs(pDnsHdr->flags);
    //iQueryNum = ntohs(pDnsHdr->questNum);
    iRespNum = ntohs(pDnsHdr->answerNum);
    iAuthRespNum = ntohs(pDnsHdr->authorNum);
    //iAdditionNum = ntohs(pDnsHdr->additionNum);

    //0 为DNS查询报文，1为应答报文
    if (iFlags & 0x8000)
    {
        if ((iFlags & 0x0100) && !(iFlags & 0x0080))
        {
            printf("Server can not do recursive quires\n");
            return;
        }

        //flags低位值为3，标识服务器没有与请求域名相应的记录
        if ((iFlags & 0x7000) != 0)
        {
            printf("No corresponding domain name entry\n");
            return;
        }

        //查看标志位AA，看是否为权威应答
        if ((iFlags & 0x0400) != 0)
        {
            printf("Authoritative anwser : \n");
        }
        else
        {
            printf("None-authoritative anwser : \n");
        }

        unsigned char *pTraceResponse;
        //指针移向应答报文中的第一个查询记录，因为一般情况下应答报文均会首先附带一个对应的查询记录
        pTraceResponse = recvBuff + sizeof(DNSHDR);

        //获取域名信息，和组装request里的过程相反
        char queryDomain[256] = { 0 };
        trans_domain(pTraceResponse, -1, recvBuff, numbytes, queryDomain);
        printf("Query Domain: %s\n", queryDomain);

        // if ((pTraceResponse[0] & 0x01) && (pTraceResponse[1] & 0x01)) 
        // {
        //     printf("Type : CAA\n");
        // }

        //跳过查询类型和查询类两个字段，指针指向第一个应答记录
        pTraceResponse += (sizeof(short) * 2);
        struct in_addr address;
        pRESPONSEHDR pResponse;

        printf("answerNum: %d\n", iRespNum);

        unsigned char *pTemp = pTraceResponse;

        for (int i = 0; i < iAuthRespNum; i++)
        {
            //指针跳过应答记录的“域名”字段，此域名字段一般为一个域名指针，以0xC0开始
            char respDomain[256] = {0};
            printf("Auth Resp Domain: %s  ", trans_domain(pTemp, -1, recvBuff, numbytes, respDomain));

            pResponse = (pRESPONSEHDR)pTemp;
            //printf("ttl: %u\n", ntohl(pResponse->ttl));
            uint16_t type = ntohs(pResponse->type);
            //unsigned short len = ntohs(pResponse->length);
            switch (type)
            {
            case DNS_TYPE_SOA: 
                //todo
                break;

            default:
                break;
            }
        }


        for (int i = 0; i < iRespNum; i++)
        {
            //指针跳过应答记录的“域名”字段，此域名字段一般为一个域名指针，以0xC0开始
            //unsigned char *pTmp = recvBuff + getOffset(pTraceResponse);
            char respDomain[256] = {0};
            printf("Resp Domain: %s  ", trans_domain(pTraceResponse, -1, recvBuff, numbytes, respDomain));
            //pTraceResponse += sizeof(short);

            pResponse = (pRESPONSEHDR)pTraceResponse;
            //printf("ttl: %u\n", ntohl(pResponse->ttl));
            uint16_t type = ntohs(pResponse->type);
            unsigned short classes = ntohs(pResponse->classes);
            uint32_t ttl = ntohl(pResponse->ttl);
            unsigned short len = ntohs(pResponse->length);
            pTraceResponse += sizeof(RESPONSEHDR);
            char *addr = NULL;
            DnsRecord record;
            record.type = type;
            record.ttl = ttl;
            switch (type)
            {
            case DNS_TYPE_A: //这条应答记录返回的是与之前查询所对应的IP地址
                printf("A  ");
                if (classes == 1)
                    printf("IN  ");
                else
                    printf("%d  ", classes);
                printf("TTL:%d  ", ttl);

                address.s_addr = *(unsigned int *)pTraceResponse;
                addr = inet_ntoa(address);
                record.value.emplace_back(addr);
                records->emplace_back(record);
                if (i == iRespNum - 1) //最后一条记录显示句号，否则显示分号
                {
                    printf("%s .\n", addr);
                }
                else
                {
                    printf("%s ;\n", addr);
                }

                //指针移过应答记录的IP地址字段，指向下一条应答记录
                pTraceResponse += sizeof(int);
                break;
            case DNS_TYPE_CNAME: //这条应答记录为所查询主机的一个别名，这里本程序直接跳过这条记录
                {
                    printf("CNAME  ");
                    if (classes == 1)
                        printf("IN  ");
                    else
                        printf("%d  ", classes);
                    printf("TTL:%d  ", ttl);                    
                    //获取域名信息，和组装request里的过程相反
                    char cname[256] = { 0 };
                    trans_domain(pTraceResponse, len, recvBuff, numbytes, cname); //transDomain会移动pTraceResponse指针
                    printf("%s\n", cname);
                    record.value.emplace_back(cname);
                    records->emplace_back(record);
                    break;
                }
            case DNS_TYPE_AAAA:
                {
                    printf("AAAA  ");
                    if (classes == 1)
                        printf("IN  ");
                    else
                        printf("%d  ", classes);
                    printf("TTL:%d  ", ttl);                    
                    //网络字节流 ——》IP字符串     
                    char buf[INET6_ADDRSTRLEN] = {0};
                    if(inet_ntop(AF_INET6, pTraceResponse, buf, INET6_ADDRSTRLEN) == NULL){       
                        perror("inet ntop\n");     
                    }   
                    else
                    {
                        record.value.emplace_back(buf);
                        records->emplace_back(record);
                        printf("%s\n", buf);
                    }
                    pTraceResponse += ntohs(pResponse->length);
                    break;                
                }
            case DNS_TYPE_CAA: 
                {
                    printf("CAA  ");
                    if (classes == 1)
                        printf("IN  ");
                    else
                        printf("%d  ", classes);
                    printf("TTL:%d  ", ttl);                    
                    int caflag = *pTraceResponse++;
                    if (caflag < 0 || caflag > 255)
                    {
                        printf("invalid caflag\n");
                        break;
                    }

                    printf("%s  ", queryDomain);

                    // tag目前有三种issue、issuewild、iodef
                    // issue表示：CA授权单个证书颁发机构发布的任何类型的域名证书
                    // issuewild表示：CA授权单个证书颁发机构发布主机名的通配符证书
                    // iodef表示：CA可以将违规的颁发记录URL发送给某个电子邮箱
                    unsigned short taglen = *pTraceResponse++;
                    if (taglen > 9/* length of "issuewild"*/)
                    {
                        printf("invalid taglen\n");
                        break;
                    }

                    string str_tag((char*)pTraceResponse, taglen);
                    pTraceResponse += taglen;

                    string str_ca((char*)pTraceResponse, len - taglen - 2);
                    pTraceResponse += (len - taglen - 2);
                    printf("%s  %s", str_tag.c_str(), str_ca.c_str());

                    record.value.emplace_back(str_tag);
                    record.value.emplace_back(str_ca);
                    records->emplace_back(record);
                    printf("\n");
                    break;
                }
            case DNS_TYPE_SOA:
                //todo

            default:
                printf("unparsed response type: %u\n", type);
                break;
            }
        }
        printf("\n\n");
    }
    else //标志字段最高位不为1，表示不是一个DNS应答报文，不做任何处理
    {
        printf("Invalid DNS resolution! \n\n");
    }
}

int get_dns_type(char *p)
{
    if (strcasecmp("A", p) == 0)
        return DNS_TYPE_A;
    else if (strcasecmp("AAAA", p) == 0)
        return DNS_TYPE_AAAA;
    else if (strcasecmp("CNAME", p) == 0)
        return DNS_TYPE_CNAME;
    else if (strcasecmp("CAA", p) == 0)
        return DNS_TYPE_CAA;
    // else if (strcasecmp("SOA", p) == 0)
    //     return DNS_TYPE_SOA;        
    return DNS_TYPE_A;
}

int main(int argc, char* argv[])
{
    //DnsLookup dns;
    DnsLookup dns({"114.114.114.114", "8.8.8.8", "1.1.1.1", "9.9.9.9"}); 
    const char *domain = "baidu.com";
    int dns_type = DNS_TYPE_A;
    if (argc >= 2) 
        domain = (const char*)argv[1];
    if (argc >= 3)
        dns_type = get_dns_type(argv[2]);

    int ret = dns.Lookup(domain, dns_type);
    if (ret == 0) {
        const vector<DnsRecord> *records = dns.get_dns_records();
        for (auto &it : *records) {
            printf("type: %d, ttl: %d, ", it.type, it.ttl);
            for (auto &it2 : it.value) {
                printf("%s ", it2.c_str());
            }
            printf("\n");
        }
    }
    return 0;
}
