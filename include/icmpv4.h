#ifndef ICMPV4_H
#define ICMPV4_H

#include "syshead.h"
#include "skbuff.h"

#define ICMP_V4_REPLY           0x00
#define ICMP_V4_DST_UNREACHABLE 0x03
#define ICMP_V4_SRC_QUENCH      0x04
#define ICMP_V4_REDIRECT        0x05
#define ICMP_V4_ECHO            0x08
#define ICMP_V4_ROUTER_ADV      0x09
#define ICMP_V4_ROUTER_SOL      0x0a
#define ICMP_V4_TIMEOUT         0x0b
#define ICMP_V4_MALFORMED       0x0c

struct icmp_v4 {
    uint8_t type;                           // ICMP消息类型
    uint8_t code;                           // 具体描述ICMP消息的意义
    uint16_t csum;                          // 校验和
    uint8_t data[];                         // ICMP内容
} __attribute__((packed));

struct icmp_v4_echo {                       // ping
    uint16_t id;                            // 发送方确定哪个进程处理回复
    uint16_t seq;                           // 请求编号，从0开始逐渐加1
    uint8_t data[];                         // optional，可以包含时间戳
} __attribute__((packed));

struct icmp_v4_dst_unreachable {
    uint8_t unused;                         // 没有使用
    uint8_t len;                            // 原始数据报的长度，对于IPv4，单位是4字节
    uint16_t var;                           // 依赖于ICMP code
    uint8_t data[];                         // 最后，尽可能多地将导致Destination不可达状态的原始IP数据包放入data字段中。
} __attribute__((packed));


void icmpv4_incoming(struct sk_buff *skb);
void icmpv4_reply(struct sk_buff *skb);

#endif
