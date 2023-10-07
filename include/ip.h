#ifndef IPV4_H
#define IPV4_H
#include "syshead.h"
#include "ethernet.h"
#include "skbuff.h"
#include "sock.h"

#define IPV4 0x04
#define IP_TCP 0x06
#define ICMPV4 0x01

#define IP_HDR_LEN sizeof(struct iphdr)
#define ip_len(ip) (ip->len - (ip->ihl * 4))

#ifdef DEBUG_IP
#define ip_dbg(msg, hdr)                                                \
    do {                                                                \
        print_debug("ip "msg" (ihl: %hhu version: %hhu tos: %hhu "   \
                    "len %hu id: %hu frag_offset: %hu ttl: %hhu " \
                    "proto: %hhu csum: %hx " \
                    "saddr: %hhu.%hhu.%hhu.%hhu daddr: %hhu.%hhu.%hhu.%hhu)", \
                    hdr->ihl,                                           \
                    hdr->version, hdr->tos, hdr->len, hdr->id,          \
                    hdr->frag_offset, hdr->ttl, hdr->proto, hdr->csum,   \
                    hdr->saddr >> 24, hdr->saddr >> 16, hdr->saddr >> 8, hdr->saddr >> 0, \
                    hdr->daddr >> 24, hdr->daddr >> 16, hdr->daddr >> 8, hdr->daddr >> 0); \
    } while (0)
#else
#define ip_dbg(msg, hdr)
#endif

struct iphdr {
    uint8_t ihl : 4; /* TODO: Support Big Endian hosts */   // 4bit=半字节，报头长度，单位是4字节
    uint8_t version : 4;                                    // 4bit=半字节，版本，这里交换了位置，需要考虑主机是大端还是小端
    uint8_t tos;                                            // 1字节，服务类型
    uint16_t len;                                           // IP数据报总长
    uint16_t id;                                            // IP数据报标识，当数据报因为MTU分片时用以表示同一个数据报
    uint16_t frag_offset;                                   // 3bit的分片标志位，13bit分片偏移，以8字节为单位
    uint8_t ttl;                                            // 计算数据报生存时间，路由转发时首先-1，如果为0就丢弃不转发，所以设为1时只能在局域网内
    uint8_t proto;                                          // 1字节，标识上层使用的协议，TCP是6，UDP是16
    uint16_t csum;                                          // 2字节首部校验和，求和，进位循环加在最后，最后求反
    uint32_t saddr;                                         // 源IP地址
    uint32_t daddr;                                         // 目的IP地址
    uint8_t data[];                                         // 上层数据
} __attribute__((packed));

static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
    return (struct iphdr *)(skb->head + ETH_HDR_LEN);
}

static inline uint32_t ip_parse(char *addr)
{
    uint32_t dst = 0;
    
    if (inet_pton(AF_INET, addr, &dst) != 1) {
        perror("ERR: Parsing inet address failed");
        exit(1);
    }

    return ntohl(dst);
}

int ip_rcv(struct sk_buff *skb);
int ip_output(struct sock *sk, struct sk_buff *skb);

#endif
