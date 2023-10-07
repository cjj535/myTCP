#ifndef TCP_H_
#define TCP_H_
#include "syshead.h"
#include "ip.h"
#include "timer.h"
#include "utils.h"

#define TCP_HDR_LEN sizeof(struct tcphdr)
#define TCP_DOFFSET sizeof(struct tcphdr) / 4

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

#define TCP_URG 0x20
#define TCP_ECN 0x40
#define TCP_WIN 0x80

#define TCP_SYN_BACKOFF 500
#define TCP_CONN_RETRIES 3

#define TCP_OPT_NOOP 1
#define TCP_OPTLEN_MSS 4
#define TCP_OPT_MSS 2
#define TCP_OPT_SACK_OK 4
#define TCP_OPT_SACK 5
#define TCP_OPTLEN_SACK 2
#define TCP_OPT_TS 8

#define TCP_2MSL 60000
#define TCP_USER_TIMEOUT 180000

#define tcp_sk(sk) ((struct tcp_sock *)sk)
#define tcp_hlen(tcp) (tcp->hl << 2)

#ifdef DEBUG_TCP
extern const char *tcp_dbg_states[];
#define tcp_in_dbg(hdr, sk, skb)                                        \
    do {                                                                \
        print_debug("TCP %u.%u.%u.%u.%u > %u.%u.%u.%u.%u: " \
                    "Flags [S%uA%uP%uF%uR%u], seq %u:%u, ack %u, win %u rto %d boff %d", \
                    (uint8_t)(sk->daddr >> 24), (uint8_t)(sk->daddr >> 16), (uint8_t)(sk->daddr >> 8), (uint8_t)(sk->daddr >> 0), sk->dport, \
                    (uint8_t)(sk->saddr >> 24), (uint8_t)(sk->saddr >> 16), (uint8_t)(sk->saddr >> 8), (uint8_t)(sk->saddr >> 0), sk->sport, \
                    hdr->syn, hdr->ack, hdr->psh, hdr->fin, hdr->rst, hdr->seq - tcp_sk(sk)->tcb.irs, \
                    hdr->seq + skb->dlen - tcp_sk(sk)->tcb.irs,         \
                    hdr->ack_seq - tcp_sk(sk)->tcb.iss, hdr->win, tcp_sk(sk)->rto, tcp_sk(sk)->backoff); \
    } while (0) 

#define tcp_out_dbg(hdr, sk, skb)                                       \
    do {                                                                \
        print_debug("TCP %u.%u.%u.%u.%u > %u.%u.%u.%u.%u: " \
                    "Flags [S%uA%uP%uF%uR%u], seq %u:%u, ack %u, win %u rto %d boff %d", \
                    (uint8_t)(sk->saddr >> 24), (uint8_t)(sk->saddr >> 16), (uint8_t)(sk->saddr >> 8), (uint8_t)(sk->saddr >> 0), sk->sport, \
                    (uint8_t)(sk->daddr >> 24), (uint8_t)(sk->daddr >> 16), (uint8_t)(sk->daddr >> 8), (uint8_t)(sk->daddr >> 0), sk->dport, \
                    hdr->syn, hdr->ack, hdr->psh, hdr->fin, hdr->rst, hdr->seq - tcp_sk(sk)->tcb.iss, \
                    hdr->seq + skb->dlen - tcp_sk(sk)->tcb.iss,         \
                    hdr->ack_seq - tcp_sk(sk)->tcb.irs, hdr->win, tcp_sk(sk)->rto, tcp_sk(sk)->backoff); \
    } while (0)

#define tcpsock_dbg(msg, sk)                                            \
    do {                                                                \
        print_debug("TCP x:%u > %u.%u.%u.%u.%u (snd_una %u, snd_nxt %u, snd_wnd %u, " \
                    "snd_wl1 %u, snd_wl2 %u, rcv_nxt %u, rcv_wnd %u recv-q %d send-q %d " \
                    "rto %d boff %d) state %s: "msg, \
                    sk->sport, (uint8_t)(sk->daddr >> 24), (uint8_t)(sk->daddr >> 16), (uint8_t)(sk->daddr >> 8), (uint8_t)(sk->daddr >> 0), \
                    sk->dport, tcp_sk(sk)->tcb.snd_una - tcp_sk(sk)->tcb.iss,      \
                    tcp_sk(sk)->tcb.snd_nxt - tcp_sk(sk)->tcb.iss, tcp_sk(sk)->tcb.snd_wnd, \
                    tcp_sk(sk)->tcb.snd_wl1, tcp_sk(sk)->tcb.snd_wl2,   \
                    tcp_sk(sk)->tcb.rcv_nxt - tcp_sk(sk)->tcb.irs, tcp_sk(sk)->tcb.rcv_wnd, \
                    sk->receive_queue.qlen, sk->write_queue.qlen, tcp_sk(sk)->rto, tcp_sk(sk)->backoff, \
                    tcp_dbg_states[sk->state]);                         \
    } while (0)

#define tcp_set_state(sk, state)                                        \
    do {                                                                \
        tcpsock_dbg("state is now "#state, sk);                         \
        __tcp_set_state(sk, state);                                     \
    } while (0)

#define return_tcp_drop(sk, skb)                          \
    do {                                                  \
        tcpsock_dbg("dropping packet", sk);               \
        return __tcp_drop(sk, skb);                       \
    } while (0)

#define tcp_drop(tsk, skb)                      \
    do {                                        \
        tcpsock_dbg("dropping packet", sk);               \
        __tcp_drop(tsk, skb);                   \
    } while (0)

#else
#define tcp_in_dbg(hdr, sk, skb)
#define tcp_out_dbg(hdr, sk, skb)
#define tcpsock_dbg(msg, sk)
#define tcp_set_state(sk, state)  __tcp_set_state(sk, state)
#define return_tcp_drop(tsk, skb) return __tcp_drop(tsk, skb)
#define tcp_drop(tsk, skb) __tcp_drop(tsk, skb)
#endif

struct tcphdr {
    uint16_t sport;                 // 源端口号
    uint16_t dport;                 // 目的端口号
    uint32_t seq;                   // 序列号，初始序列号随机选取，防止伪造TCP攻击
    uint32_t ack_seq;               // 确认号，已收到的数据，下一步希望发送的数据
    uint8_t rsvd : 4;               // reserved
    uint8_t hl : 4;                 // 头部长度，以4字节为单位
    uint8_t fin : 1,                // FIN (F) indicates that the sender has finished sending data.
            syn : 1,                // SYN (S) is used to synchronize sequence numbers in the initial handshake.
            rst : 1,                // RST (R) resets the TCP connection.
            psh : 1,                // PSH (P) is used to indicate that the receiver should “push” the data to the application as soon as possible.
            ack : 1,                // ACK (A) field is used to communicate the state of the TCP handshake. It stays on for the remainder of the connection.
            urg : 1,                // Urgent Pointer (U) indicates that the segment contains prioritized data.
            ece : 1,                // ECN Echo (E) informs that the sender received a congestion notification.
            cwr : 1;                // Congestion Window Reduced (C) is used for informing that the sender reduced its sending rate.
    uint16_t win;                   // 建议窗口长度，最大值是65535
    uint16_t csum;                  // 校验和
    uint16_t urp;                   // 紧急指针，当urg位置1时，指向紧急数据的起始位置
    uint8_t data[];                 // 上层数据
} __attribute__((packed));

struct tcp_options {
    uint16_t options;
    uint16_t mss;                   // The Maximum Segment Size (MSS) option informs the maximum TCP segment size the TCP implementation is willing to receive. The typical value for this is 1460 bytes in IPv4.
    uint8_t sack;                   // The Selective Acknowledgment (SACK) option优化大量包丢失的场景，提醒对方选择性补发之前的包
                                    // The Window Scale option increases the limited 16-bit window size. 对上面的建议窗口长度乘以WS值，用以放大窗长
                                    // The Timestamps option 放时间戳，可用以检测RTT
};

struct tcp_opt_mss {
    uint8_t kind;
    uint8_t len;
    uint16_t mss;
} __attribute__((packed));

struct tcpiphdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t proto;
    uint16_t tlen;
} __attribute__((packed));

enum tcp_states {
    TCP_LISTEN, /* represents waiting for a connection request from any remote
                   TCP and port. */
    TCP_SYN_SENT, /* represents waiting for a matching connection request
                     after having sent a connection request. */
    TCP_SYN_RECEIVED, /* represents waiting for a confirming connection
                         request acknowledgment after having both received and sent a
                         connection request. */
    TCP_ESTABLISHED, /* represents an open connection, data received can be
                        delivered to the user.  The normal state for the data transfer phase
                        of the connection. */
    TCP_FIN_WAIT_1, /* represents waiting for a connection termination request
                       from the remote TCP, or an acknowledgment of the connection
                       termination request previously sent. */
    TCP_FIN_WAIT_2, /* represents waiting for a connection termination request
                       from the remote TCP. */
    TCP_CLOSE, /* represents no connection state at all. */
    TCP_CLOSE_WAIT, /* represents waiting for a connection termination request
                       from the local user. */
    TCP_CLOSING, /* represents waiting for a connection termination request
                    acknowledgment from the remote TCP. */
    TCP_LAST_ACK, /* represents waiting for an acknowledgment of the
                     connection termination request previously sent to the remote TCP
                     (which includes an acknowledgment of its connection termination
                     request). */
    TCP_TIME_WAIT, /* represents waiting for enough time to pass to be sure
                      the remote TCP received the acknowledgment of its connection
                      termination request. */
};

struct tcb {
    uint32_t snd_una; /* oldest unacknowledged sequence number */
    uint32_t snd_nxt; /* next sequence number to be sent */
    uint32_t snd_wnd;
    uint32_t snd_up;
    uint32_t snd_wl1;
    uint32_t snd_wl2;
    uint32_t iss;
    uint32_t rcv_nxt; /* next sequence number expected on an incoming segments, and
                         is the left or lower edge of the receive window */
    uint32_t rcv_wnd;
    uint32_t rcv_up;
    uint32_t irs;
};

struct tcp_sack_block {
    uint32_t left;
    uint32_t right;
} __attribute__((packed));

struct tcp_sock {
    struct sock sk;
    int fd;
    uint16_t tcp_header_len;
    struct tcb tcb;
    uint8_t flags;
    uint8_t backoff;
    int32_t srtt;
    int32_t rttvar;
    uint32_t rto;
    struct timer *retransmit;
    struct timer *delack;
    struct timer *keepalive;
    struct timer *linger;
    uint8_t delacks;
    uint16_t rmss;
    uint16_t smss;
    uint16_t cwnd;
    uint32_t inflight;

    uint8_t sackok;
    uint8_t sacks_allowed;
    uint8_t sacklen;
    struct tcp_sack_block sacks[4];

    uint8_t tsopt;
    
    struct sk_buff_head ofo_queue; /* Out-of-order queue */
};

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
    return (struct tcphdr *)(skb->head + ETH_HDR_LEN + IP_HDR_LEN);
}

void tcp_init();
void tcp_in(struct sk_buff *skb);
int tcp_checksum(struct tcp_sock *sock, struct tcphdr *thdr);
void tcp_select_initial_window(uint32_t *rcv_wnd);

int generate_iss();
struct sock *tcp_alloc_sock();
int tcp_v4_init_sock(struct sock *sk);
int tcp_init_sock(struct sock *sk);
void __tcp_set_state(struct sock *sk, uint32_t state);
int tcp_v4_checksum(struct sk_buff *skb, uint32_t saddr, uint32_t daddr);
int tcp_v4_connect(struct sock *sk, const struct sockaddr *addr, int addrlen, int flags);
int tcp_connect(struct sock *sk);
int tcp_disconnect(struct sock *sk, int flags);
int tcp_write(struct sock *sk, const void *buf, int len);
int tcp_read(struct sock *sk, void *buf, int len);
int tcp_receive(struct tcp_sock *tsk, void *buf, int len);
int tcp_input_state(struct sock *sk, struct tcphdr *th, struct sk_buff *skb);
int tcp_send_synack(struct sock *sk);
int tcp_send_next(struct sock *sk, int amount);
int tcp_send_ack(struct sock *sk);
void *tcp_send_delack(void *arg);
int tcp_queue_fin(struct sock *sk);
int tcp_send_fin(struct sock *sk);
int tcp_send(struct tcp_sock *tsk, const void *buf, int len);
int tcp_send_reset(struct tcp_sock *tsk);
int tcp_send_challenge_ack(struct sock *sk, struct sk_buff *skb);
int tcp_recv_notify(struct sock *sk);
int tcp_close(struct sock *sk);
int tcp_abort(struct sock *sk);
int tcp_done(struct sock *sk);
void tcp_rtt(struct tcp_sock *tsk);
void tcp_handle_fin_state(struct sock *sk);
void tcp_enter_time_wait(struct sock *sk);
void tcp_clear_timers(struct sock *sk);
void tcp_rearm_rto_timer(struct tcp_sock *tsk);
void tcp_stop_rto_timer(struct tcp_sock *tsk);
void tcp_release_rto_timer(struct tcp_sock *tsk);
void tcp_stop_delack_timer(struct tcp_sock *tsk);
void tcp_release_delack_timer(struct tcp_sock *tsk);
void tcp_rearm_user_timeout(struct sock *sk);
int tcp_calculate_sacks(struct tcp_sock *tsk);

#endif
