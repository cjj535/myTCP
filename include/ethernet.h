#ifndef ETHERNET_H_
#define ETHERNET_H_

#include <linux/if_ether.h>
#include "netdev.h"
#include "skbuff.h"
#include "syshead.h"
#include "utils.h"

#define ETH_HDR_LEN sizeof(struct eth_hdr)

#ifdef DEBUG_ETH
#define eth_dbg(msg, hdr)                                               \
    do {                                                                \
        print_debug("eth "msg" ("                                       \
                    "dmac: %.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx, " \
                    "smac: %.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx, " \
                    "ethertype: %.4hx)",                               \
                    hdr->dmac[0], hdr->dmac[1], hdr->dmac[2], hdr->dmac[3], \
                    hdr->dmac[4], hdr->dmac[5], hdr->smac[0], hdr->smac[1], \
                    hdr->smac[2], hdr->smac[3], hdr->smac[4], hdr->smac[5], hdr->ethertype); \
    } while (0)
#else
#define eth_dbg(msg, hdr)
#endif

struct sk_buff;
struct netdev;

uint8_t *skb_head(struct sk_buff *skb);

struct eth_hdr 
{
    uint8_t  dmac[6];           // 目的MAC地址，48位=6字节
    uint8_t  smac[6];           // 源MAC地址，48位=6字节
    uint16_t ethertype;         // 2字节，以太网帧类型，如果这个值不小于1536则表示是类型（IPv4，ARP），否则是payload长度
    uint8_t  payload[];         // 这里省略了4字节的tag，那么最短的payload长度是48，最长是1500，（最短以太网帧是64，与CSMA/CD碰撞检测有关）
} __attribute__((packed));      // 所有元素紧凑排列，不要对齐
                                // 省略了4字节的校验和

static inline struct eth_hdr *eth_hdr(struct sk_buff *skb)
{
    struct eth_hdr *hdr = (struct eth_hdr *)skb_head(skb);

    hdr->ethertype = ntohs(hdr->ethertype);     // 网络序（大端）转主机序（小端）

    return hdr;
}

#endif
