#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "platform.h"

#include "util.h"
#include "ip.h"
#include "tcp.h"

// TCPヘッダのフラグフィールドの値
#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

#define TCP_PCB_SIZE 16

#define TCP_PCB_STATE_FREE 0
#define TCP_PCB_STATE_CLOSED 1
#define TCP_PCB_STATE_LISTEN 2
#define TCP_PCB_STATE_SYN_SENT 3
#define TCP_PCB_STATE_SYN_RECEIVED 4
#define TCP_PCB_STATE_ESTABLISHED 5
#define TCP_PCB_STATE_FIN_WAIT1 6
#define TCP_PCB_STATE_FIN_WAIT2 7
#define TCP_PCB_STATE_CLOSING 8
#define TCP_PCB_STATE_TIME_WAIT 9
#define TCP_PCB_STATE_CLOSE_WAIT 10
#define TCP_PCB_STATE_LAST_ACK 11

#define TCP_DEFAULT_RTO 200000 /* micro seconds */
#define TCP_RETRANSMIT_DEADLINE 12 /* seconds */

// 疑似ヘッダの構造体（チェックサム計算時に使用する）
struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

// TCPヘッダの構造体
struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t off;
    uint8_t flg;
    uint16_t wnd;
    uint16_t sum;
    uint16_t up;
};

// PRCがない
struct tcp_segment_info {
    uint32_t seq;
    uint32_t ack;
    uint16_t len;
    uint16_t wnd;
    uint16_t up;
};

// コントロールブロックの構造体
struct tcp_pcb {
    int state; // コネクションの状態
    struct ip_endpoint local;   // コネクションの両端のアドレス情報
    struct ip_endpoint foreign; // 
    // 送信時に必要となる情報
    struct {
        uint32_t nxt;
        uint32_t una;
        uint16_t wnd;
        uint16_t up;
        uint32_t wl1;
        uint32_t wl2;
    } snd;
    uint32_t iss;
    // 受信時に必要となる情報
    struct {
        uint32_t nxt;
        uint16_t wnd;
        uint16_t up;
    } rcv;
    uint32_t irs;
    uint16_t mtu;
    uint16_t mss;
    // uint8_t buf[65535]; /* receive buffer */
    uint8_t buf[16]; /* receive buffer */
    struct sched_ctx ctx;
    // PCB構造体のメンバに受信キューが追加
    struct queue_head queue; /* retransmit queue */
};

struct tcp_queue_entry {
    struct timeval first; // 初回送信時刻
    struct timeval last;  // 最終送信時刻
    unsigned int rto; /* micro seconds 再送タイムアウト（前回の再送時刻からこの時間が経過したら再送を実施） */
    uint32_t seq; // セグメントのシーケンス番号（その他の情報は再送を実施するタイミングでPCBから値を取得）
    uint8_t flg; // セグメントの制御フラグ（その他の情報は再送を実施するタイミングでPCBから値を取得）
    size_t len;
    uint8_t data[];
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct tcp_pcb pcbs[TCP_PCB_SIZE];

static char *tcp_flg_ntoa(uint8_t flg) {
    static char str[9];

    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
        TCP_FLG_ISSET(flg, TCP_FLG_URG) ? 'U' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_ACK) ? 'A' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_PSH) ? 'P' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_RST) ? 'R' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_SYN) ? 'S' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_FIN) ? 'F' : '-');
    return str;
}

// デバッグ出力
static void tcp_dump(const uint8_t *data, size_t len) {
    struct tcp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct tcp_hdr *)data;
    fprintf(stderr, "      src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "      dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "      seq: %u\n", ntoh32(hdr->seq));
    fprintf(stderr, "      ack: %u\n", ntoh32(hdr->ack));
    fprintf(stderr, "      off: 0x%02x (%d)\n", hdr->off, (hdr->off >> 4) << 2);
    fprintf(stderr, "      flg: 0x%02x (%s)\n", hdr->flg, tcp_flg_ntoa(hdr->flg));
    fprintf(stderr, "      wnd: %u\n", ntoh16(hdr->wnd));
    fprintf(stderr, "      sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "       up: %u\n", ntoh16(hdr->up));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
* TCP PRotocol Control Block (PCB)
* NOTE: TCP PCB functions must be called after mutex locked
*/

static struct tcp_pcb *tcp_pcb_alloc(void) {
    struct tcp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == TCP_PCB_STATE_FREE) {
            // FREE状態のPCBを見つけて返す
            // CLOSED状態に初期化する
            pcb->state = TCP_PCB_STATE_CLOSED;
            sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }
    return NULL;
}

static void tcp_pcb_release(struct tcp_pcb *pcb) {
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    // PCB利用しているタスクがいたらこのタイミングでは解放できない
    // ・タスクを起床させてる（他のタスクに開放を任せる）
    if (sched_ctx_destroy(&pcb->ctx) == -1) {
        sched_wakeup(&pcb->ctx);
        return;
    }
    debugf("released, local=%s, foreign=%s",
        ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)),
        ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    memset(pcb, 0, sizeof(*pcb)); // pcb->state is set to TCP_PCB_STATE_FREE (0)
}

// コントロールブロックの実装
static struct tcp_pcb *tcp_pcb_select(struct ip_endpoint *local, struct ip_endpoint *foreign) {
    struct tcp_pcb *pcb, *listen_pcb = NULL;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == local->addr) && pcb->local.port == local->port) {
            // ローカルアドレスにbind可能かどうか調べるときは外部アドレスを指定せずに呼ばれる
            // ・ローカルアドレスがマッチしているので返す
            if (!foreign)
                return pcb;
            // ローカルアドレスと外部アドレスが共にマッチ
            if (pcb->foreign.addr == foreign->addr && pcb->foreign.port == foreign->port) {
                return pcb;
            }
            // 外部アドレスを指定せずにLISTENしていたらどんな外部アドレスでもマッチする
            // ・ローカルアドレス/外部アドレス共にマッチしたものが優先されるのですぐには返さない
            if (pcb->state == TCP_PCB_STATE_LISTEN) {
                if (pcb->foreign.addr == IP_ADDR_ANY && pcb->foreign.port == 0) {
                    // LISTENed with wildcard foreign address/port
                    listen_pcb = pcb;
                }
            }
        }
    }
    return listen_pcb;
}

static struct tcp_pcb *tcp_pcb_get(int id) {
    struct tcp_pcb *pcb;

    // 配列外参照はエラー
    if (id < 0 || id >= (int)countof(pcbs))
        return NULL;
    pcb = &pcbs[id];
    // 有効でないpcbはエラー
    if (pcb->state == TCP_PCB_STATE_FREE)
        return NULL;
    return pcb;
}

static int tcp_pcb_id(struct tcp_pcb *pcb) {
    return indexof(pcbs, pcb);
}

// TCPセグメントの送信
static ssize_t tcp_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, uint16_t wnd, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign) {
    uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    uint16_t total;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    hdr = (struct tcp_hdr *)buf;

    // TCPセグメントの生成
    hdr->src = local->port;
    hdr->dst = foreign->port;
    hdr->seq = hton32(seq);
    hdr->ack = hton32(ack);
    hdr->off = (sizeof(*hdr) >> 2) << 4; // 32bitを単位としたdataのoffset
    hdr->flg = flg;
    hdr->wnd = hton16(wnd);
    hdr->sum = 0;
    hdr->up = 0;
    memcpy(hdr + 1, data, len);
    pseudo.src = local->addr;
    pseudo.dst = foreign->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    total = sizeof(*hdr) + len;
    pseudo.len = hton16(total);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);
    debugf("%s => %s, len=%zu (payload=%z)",
        ip_endpoint_ntop(local, ep1, sizeof(ep1)),
        ip_endpoint_ntop(foreign, ep2, sizeof(ep2)),
        total, len);
    tcp_dump((uint8_t *)hdr, total);
    if (ip_output(IP_PROTOCOL_TCP, (uint8_t *)hdr, total, local->addr, foreign->addr) == -1) {
        return -1;
    }
    return len;
}

/*
* TCP Retransmit
* NOTE: TCP Retransmit functions must be called after mutex locked
*/

static int tcp_retransmit_queue_add(struct tcp_pcb *pcb, uint32_t seq, uint8_t flg, uint8_t *data, size_t len) {
    struct tcp_queue_entry *entry;

    entry = memory_alloc(sizeof(*entry) + len);
    if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->rto = TCP_DEFAULT_RTO; // 再送タイムアウトにデフォルト値を設定
    // セグメントのシーケンス番号と制御フラグをコピー
    entry->seq = seq;
    entry->flg = flg;
    // TCPセグメントのデータ部分をコピー（制御フラグのみでデータがない場合は0バイトのコピー）
    entry->len = len;
    memcpy(entry->data, data, entry->len);
    // 最終送信時刻にも同じ値を得れておく（0回目の再送時刻）
    gettimeofday(&entry->first, NULL);
    entry->last = entry->first;
    // 再送キューにエントリを格納
    if (!queue_push(&pcb->queue, entry)) {
        errorf("queue_push() failure");
        memory_free(entry);
        return -1;
    }
    return 0;
}

static void tcp_retransmit_queue_cleanup(struct tcp_pcb *pcb) {
    struct tcp_queue_entry *entry;

    while (1) {
        // 受信キューの先頭を覗き見る
        entry = queue_peek(&pcb->queue);
        // entryがなかったら処理を抜ける
        if (!entry)
            break;
        // ACKの応答が得られていなかったら処理を抜ける
        if (entry->seq >= pcb->snd.una)
            break;
        entry = queue_pop(&pcb->queue);
        debugf("remote, seq=%u, flags=%s, len=%u", entry->seq, tcp_flg_ntoa(entry->flg), entry->len);
        memory_free(entry);
    }
    return;
}

// TCPタイマの処理から定期的に呼び出される
static void tcp_retransmit_queue_emit(void *arg, void *data) {
    struct tcp_pcb *pcb;
    struct tcp_queue_entry *entry;
    struct timeval now, diff, timeout;

    pcb = (struct tcp_pcb *)arg;
    entry = (struct tcp_queue_entry *)data;
    // 初回送信からの経過時間を計算
    gettimeofday(&now, NULL);
    timersub(&now, &entry->first, &diff);
    // 初回送信からの時間経過がデッドラインを超えていたらコネクションを破棄する
    if (diff.tv_sec >= TCP_RETRANSMIT_DEADLINE) {
        pcb->state = TCP_PCB_STATE_CLOSED;
        sched_wakeup(&pcb->ctx);
        return;
    }
    // 再送予定時刻を計算
    timeout = entry->last;
    timeval_add_usec(&timeout, entry->rto);
    // 再送予定時刻を過ぎていたらTCPセグメントを再送する
    if (timercmp(&now, &timeout, >)) {
        tcp_output_segment(entry->seq, pcb->rcv.nxt, entry->flg, pcb->rcv.wnd, entry->data, entry->len, &pcb->local, &pcb->foreign);
        // 最終送信時刻を更新
        entry->last = now;
        // 再送タイムアウト（次の再送までの時間）を2倍の値で設定
        entry->rto *= 2;
    }
}

// TCPの送信関数
static ssize_t tcp_output(struct tcp_pcb *pcb, uint8_t flg, uint8_t *data, size_t len) {
    uint32_t seq;

    seq = pcb->snd.nxt;
    // SYNフラグが指定されるのは初回送信時なのでiss（初期送信シーケンス番号）を使う
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN))
        seq = pcb->iss;
    // シーケンス番号を消費するセグメントだけ再送キューへ格納する
    // （単純なACKセグメントやRSTセグメントは対象外）
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN) || len) {
        tcp_retransmit_queue_add(pcb, seq, flg, data, len);
    }
    // PCBの情報を使ってTCPセグメントを送信
    return tcp_output_segment(seq, pcb->rcv.nxt, flg, pcb->rcv.wnd, data, len, &pcb->local, &pcb->foreign);
}

/* rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES] */
static void tcp_segment_arrives(struct tcp_segment_info *seg, uint8_t flags, uint8_t *data, size_t len, struct ip_endpoint *local, struct ip_endpoint *foreign) {
    int acceptable = 0;
    struct tcp_pcb *pcb;
    
    pcb = tcp_pcb_select(local, foreign);
    // CLOSEされているpcbの場合の処理
    if (!pcb || pcb->state == TCP_PCB_STATE_CLOSED) {
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST))
            return;
        // 使用していないポートに何か飛んで来たらRSTを返す
        if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK))
            tcp_output_segment(0, seg->seq + seg->len, TCP_FLG_RST | TCP_FLG_ACK, 0, NULL, 0, local, foreign);
        else 
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
        return;
    }
    
    switch (pcb->state) {
        case TCP_PCB_STATE_LISTEN:
            /* 1st check for an RST */
            if (TCP_FLG_ISSET(flags, TCP_FLG_RST))
                return;
            /* 2nd check for an ACK */
            if (TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
                tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
                return;
            }
            /* 3rd check for an SYN */
            if (TCP_FLG_ISSET(flags, TCP_FLG_SYN)) {
                /*
                ignore: security/compartment check
                ignore: precedence check
                */
                // 両端の具体的なアドレスが確定する
                pcb->local = *local;
                pcb->foreign = *foreign;
                pcb->rcv.wnd = sizeof(pcb->buf); // 受信ウィンドウのサイズを設定
                pcb->rcv.nxt = seg->seq + 1; // 次に受信を期待するシーケンス番号（ACKで使われる）
                pcb->irs = seg->seq; // 初期受信シーケンス番号の保存
                pcb->iss = random(); // 初期送信シーケンス番号の採番
                tcp_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
                pcb->snd.nxt = pcb->iss + 1; // 次に送信するシーケンス番号
                pcb->snd.una = pcb->iss; // ACKが返ってきていない最後のシーケンス番号
                pcb->state = TCP_PCB_STATE_SYN_RECEIVED; // The connection state should be changed to SYN-RECEIVED
                /*
                ignore: Note that any other incoming control or data
                (combined with SYN) will be processed in the SYN-RECEIVED state,
                but processing of SYN and ACK should not be repeated.
                */
                return;
            }

            /* 4th other text or control */

            /* drop segment */
            return;
        case TCP_PCB_STATE_SYN_SENT:
            /* 1st check the ACK bit */
            if (TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
                // 送信していないシーケンス番号に対するACKだったらRSTを返す
                if (seg->ack <= pcb->iss || seg->ack > pcb->snd.nxt) {
                    tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
                    return;
                }
                // まだACKの応答が得られていないシーケンス番号に対するものだったら受け入れる
                if (pcb->snd.una <= seg->ack && seg->ack <= pcb->snd.nxt)
                    acceptable = 1;
            }
            /* 2nd check the RST bit */

            /* 3rd check security and precedence */

            /* 4th check the SYN bit */
            if (TCP_FLG_ISSET(flags, TCP_FLG_SYN)) {
                // 次に受信するシーケンス番号を更新する
                pcb->rcv.nxt = seg->seq + 1;
                // 相手の初期シーケンス番号を保存する
                pcb->irs = seg->seq;

                // ACKを受け入れた際の処理
                // ・未確認のシーケンス番号を更新（ACKの値は「次に受信すべきシーケンス番号」を示すのでACKの値と同一のシーケンス番号の確認は取れていない）
                // ・再送キューからACKによって到達が確認できているTCPセグメントを削除
                if (acceptable) {
                    pcb->snd.una = seg->ack; // seg->ack: サーバ側のpcb->rcv.nxt
                    tcp_retransmit_queue_cleanup(pcb);
                }
                if (pcb->snd.una > pcb->iss) {
                    // ESTABLISHED状態へ移行
                    pcb->state = TCP_PCB_STATE_ESTABLISHED;
                    // 相手にSYNに対するACKを返す
                    tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
                    
                    /* NOTE: not specified in the RFC793, but send window initialization required */
                    pcb->snd.wnd = seg->wnd;
                    pcb->snd.wl1 = seg->seq;
                    pcb->snd.wl2 = seg->ack;
                    // 状態の変化を待っているスレッドを起床
                    sched_wakeup(&pcb->ctx);
                    /* ignore: continue processing at the sixth step below where the URG bit is checked */
                    return;
                } else {
                    // 同時オープン（両方が同時にSYNを送った場合）に対処するためのコード
                    pcb->state = TCP_PCB_STATE_SYN_RECEIVED;
                    tcp_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
                    /* ignore: If there are other controls or text in the segment, queue them for processing after the ESTABLISHED state has been reached */
                    return;
                }
            }
            /* 5th, if neither of the SYN or RST bits is set then drop the segment and return */

            /* drop segment */
            return;
    }
    /* Otherwise */

    /* 1st check sequence number */
    // 受信データのlenとrcv.wndでacceptableか確認
    // sequenceも確認
    switch (pcb->state) {
        case TCP_PCB_STATE_SYN_RECEIVED:
        case TCP_PCB_STATE_ESTABLISHED:
        case TCP_PCB_STATE_FIN_WAIT1:
        case TCP_PCB_STATE_FIN_WAIT2:
        case TCP_PCB_STATE_CLOSE_WAIT:
        case TCP_PCB_STATE_LAST_ACK:
            if (!seg->len) {
                if (!pcb->rcv.wnd) {
                    if (seg->seq == pcb->rcv.nxt)
                        acceptable = 1;
                } else {
                    if (pcb->rcv.nxt <= seg->seq && seg->seq < pcb->rcv.nxt + pcb->rcv.wnd)
                        acceptable = 1;
                }
            } else {
                if (!pcb->rcv.wnd) {
                    // not acceptable
                } else {
                    if ((pcb->rcv.nxt <= seg->seq && seg->seq < pcb->rcv.nxt + pcb->rcv.wnd) ||
                        (pcb->rcv.nxt <= seg->seq + seg->len - 1 && seg->seq + seg->len - 1 < pcb->rcv.nxt + pcb->rcv.wnd))
                        acceptable = 1;
                }
            }
    }
    if (!acceptable) {
        if (!TCP_FLG_ISSET(flags, TCP_FLG_RST))
            tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
        return;
    }
    /*
    In the following it is assumed that the segment is the idalized
    segment that begins at RCV.NXT and does not exceed the window.
    One could tailor actual segments ot fit this assumption by
    trimming off any portions that lie outside hte window (include
    SYN and FIN), and only processing further if the segment then 
    begins at RCV.NXT. Segments with higher begining sequence
    numbers may be held for later processing.
    */

    /* 2nd check the RST bit */

    /* 3rd check security and precedence (ignore) */

    /* 4th check the SYN bit */

    /* 5th check the ACK field */
    if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
        // if the ACK bit is off drop the segment and return
        return;
    }
    switch (pcb->state) {
        case TCP_PCB_STATE_SYN_RECEIVED:
            /* If SND.UNA <= SEG.ACK <= SND.NXT then enter ESTABLISHED state */
            // 送信セグメントに対する妥当なACKかどうかの判断
            if (pcb->snd.una <= seg->ack && seg->ack <= pcb->snd.nxt) {
                // ESTABLISHEDの状態に移行（コネクション確立）
                pcb->state = TCP_PCB_STATE_ESTABLISHED;
                // PCBの状態が変化を待っているスレッドを起動
                sched_wakeup(&pcb->ctx);
            } else {
                // if the segment acknowledgement is not acceptable, form a reset segment,
                // <SEQ=SEG.ACK><CTL=RST>
                tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
                return;
            }
            /* fall through */
        case TCP_PCB_STATE_ESTABLISHED:
        case TCP_PCB_STATE_FIN_WAIT1:
        case TCP_PCB_STATE_FIN_WAIT2:
        case TCP_PCB_STATE_CLOSE_WAIT:
            // まだACKを受け取っていない送信データに対するACKかどうか
            if (pcb->snd.una < seg->ack && seg->ack <= pcb->snd.nxt) {
                /////////////////////////////////////////////////// 複数のパケットに分割して送った場合、つじつまが合わない気がする ///////////////////////////////////////////////////
                pcb->snd.una = seg->ack;
            
                tcp_retransmit_queue_cleanup(pcb);
                /* ignore: Users should receive positive acknowledgements for buffers
                        which have been SENT and fully acknowledged (i.e., SEND buffer should be returned with "ok" response) */
                
                // wl1: segment sequence number used for last window update
                // wl2: segment acknowledgment number used for last window update
                if (pcb->snd.wl1 < seg->seq || (pcb->snd.wl1 == seg->seq && pcb->snd.wl2 <= seg->ack)) {
                    pcb->snd.wnd = seg->wnd;
                    pcb->snd.wl2 = seg->seq;
                    pcb->snd.wl2 = seg->ack;
                }
            } else if (seg->ack < pcb->snd.una) {
                // ignore 既に確認済みのACK
            } else if (seg->ack > pcb->snd.nxt) {
                tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
                return;
            }
            switch (pcb->state) {
                case TCP_PCB_STATE_FIN_WAIT1:
                    // seg->ack未満は受信済み == pcb->snd.nxt未満は送信済
                    if (seg->ack == pcb->snd.nxt)
                        pcb->state = TCP_PCB_STATE_FIN_WAIT2;
                    break;
                case TCP_PCB_STATE_FIN_WAIT2:
                    // if the FIN received, enter TIME-WAIT state.
                    break;
                case TCP_PCB_STATE_CLOSE_WAIT:
                    // time wait (do nothing)
                    break;
            }
            break;
        case TCP_PCB_STATE_LAST_ACK:
            if (seg->ack == pcb->snd.nxt) {
                pcb->state = TCP_PCB_STATE_CLOSED;
                tcp_pcb_release(pcb);
            }
            return;
    }
    /* 6th, check the URG bit (ignore) */

    /* 7th, process the segment text */
    switch (pcb->state) {
        case TCP_PCB_STATE_ESTABLISHED:
            // 受信データをバッファにコピーしてACKを返す
            if (len) {
                memcpy(pcb->buf + (sizeof(pcb->buf) - pcb->rcv.wnd), data, len);
                pcb->rcv.nxt = seg->seq + seg->len;
                pcb->rcv.wnd -= len;
                tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
                sched_wakeup(&pcb->ctx); // 別スレッドに通知
            }
            break;
        case TCP_PCB_STATE_FIN_WAIT2:
            // receive FIN, and send ACK
            break;
        case TCP_PCB_STATE_LAST_ACK:
            break;
    }
    /* 8th, check the FIN bit */
    if (TCP_FLG_ISSET(flags, TCP_FLG_FIN)) {
        switch (pcb->state) {
            case TCP_PCB_STATE_CLOSED:
            case TCP_PCB_STATE_LISTEN:
                // ignore
                return;
            case TCP_PCB_STATE_SYN_SENT:
                // can't rearch here
                return;
        }
        // 受け取るstateのみ到達
        pcb->rcv.nxt = seg->seq + 1;
        tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
        switch (pcb->state) {
            case TCP_PCB_STATE_SYN_RECEIVED:
            case TCP_PCB_STATE_ESTABLISHED:
                pcb->state = TCP_PCB_STATE_CLOSE_WAIT;
                sched_wakeup(&pcb->ctx);
                break;
            case TCP_PCB_STATE_FIN_WAIT1:
                if (seg->ack == pcb->snd.nxt)
                    pcb->state = TCP_PCB_STATE_TIME_WAIT;
                else
                    pcb->state = TCP_PCB_STATE_CLOSING;
                break;
            case TCP_PCB_STATE_FIN_WAIT2:
                pcb->state = TCP_PCB_STATE_TIME_WAIT;
                break;
            case TCP_PCB_STATE_CLOSE_WAIT:
                break;
            case TCP_PCB_STATE_LAST_ACK:
                break;
        }
    }
    return;
}

// TCPセグメントの入力
static void tcp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface) {
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct ip_endpoint local, foreign;
    uint16_t hlen;
    struct tcp_segment_info seg;

    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;
    }
    hdr = (struct tcp_hdr *)data;

    // UDPと同様に疑似ヘッダを含めて計算する
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.len = hton16(len); // TCP Length
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }

    // 送信元または宛先どちらかのアドレスがブロードキャストアドレスだった場合にはエラーメッセージを出力して中断する
    if (src == IP_ADDR_BROADCAST) {
        errorf("error: src is broadcast address");
        return;
    }
    if (dst == IP_ADDR_BROADCAST) {
        errorf("error: dst is broadcast address");
        return;
    }

    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
        ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
        ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
        len, len - sizeof(*hdr));
    tcp_dump(data, len);

    local.addr = dst;
    local.port = hdr->dst;
    foreign.addr = src;
    foreign.port = hdr->src;
    hlen = (hdr->off >> 4) << 2;
    seg.seq = ntoh32(hdr->seq);
    seg.ack = ntoh32(hdr->ack);
    seg.len = len - hlen; // contextの長さ
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
        seg.len++; // SYN flag consumes one sequence number
    }
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
        seg.len++; // FIN flag consumes one sequence number
    }
    seg.wnd = ntoh16(hdr->wnd);
    seg.up = ntoh16(hdr->up);
    mutex_lock(&mutex);
    tcp_segment_arrives(&seg, hdr->flg, (uint8_t *)hdr + hlen, len - hlen, &local, &foreign);
    mutex_unlock(&mutex);
    return;
}

static void tcp_timer(void) {
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == TCP_PCB_STATE_FREE)
            continue;
        // 受信キューの全てのエントリに対してtcp_retransmit_queue_emit()を実行する
        queue_foreach(&pcb->queue, tcp_retransmit_queue_emit, pcb);
    }
    mutex_unlock(&mutex);
}

static void event_handler(void *arg) {
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state != TCP_PCB_STATE_FREE) {
            sched_interrupt(&pcb->ctx);
        }
    }
    mutex_unlock(&mutex);
}

int tcp_init(void) {
    struct timeval interval = {0, 100000};

    if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) == -1) {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    net_event_subscribe(event_handler, NULL);
    
    if (net_timer_register(interval, tcp_timer) == -1) {
        errorf("net_timer_register() failure");
        return -1;
    }
    return 0;
}

/*
* TCP User Command (RFC793)
*/

// pcbを確保してlocalとforeignを入れて
// LISTENにしてSTATE_ESTABLISHEDになるまで待機する
// LISTEN -> SYN_RECEIVED -> ESTABLISHED
int tcp_open_rfc793(struct ip_endpoint *local, struct ip_endpoint *foreign, int active) {
    struct tcp_pcb *pcb;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];
    int state, id;

    mutex_lock(&mutex);
    pcb = tcp_pcb_alloc();
    if (!pcb) {
        errorf("tcp_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }
    // 能動的なオープン
    if (active) {
        debugf("active open: local=%s, foreign=%s, connecting...",
            ip_endpoint_ntop(local, ep1, sizeof(ep1)), ip_endpoint_ntop(foreign, ep2, sizeof(ep2)));
        pcb->local = *local;
        pcb->foreign = *foreign;
        pcb->rcv.wnd = sizeof(pcb->buf);
        pcb->iss = random(); // シーケンス番号の初期値を採番
        // SYNセグメントを送信
        if (tcp_output(pcb, TCP_FLG_SYN, NULL, 0) == -1) {
            errorf("tcp_output() failure");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            mutex_unlock(&mutex);
            return -1;
        }
        // またACKの確認が得られていないシーケンス番号として仮定
        pcb->snd.una = pcb->iss;
        // 次に送信すべきシーケンス番号を設定
        pcb->snd.nxt = pcb->iss + 1;
        pcb->state = TCP_PCB_STATE_SYN_SENT;
    } else {
        debugf("passive open: local=%s, waiting for connection...", ip_endpoint_ntop(local, ep1, sizeof(ep1)));
        pcb->local = *local;
        // RFC739の仕様だと外部アドレスを限定してLISTEN可能（ソケットAPIではできない）
        if (foreign) {
            pcb->foreign = *foreign;
        }
        pcb->state = TCP_PCB_STATE_LISTEN;
    }
AGAIN:
    state = pcb->state;
    /* waiting for state changed */
    while (pcb->state == state) {
        // シグナルによる割り込み発生（EINTR）
        if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
            debugf("interrupted");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            mutex_unlock(&mutex);
            errno = EINTR;
            return -1;
        }
    }
    if (pcb->state != TCP_PCB_STATE_ESTABLISHED) {
        // SYN_RECEIVEDの状態だったらリトライ
        if (pcb->state == TCP_PCB_STATE_SYN_RECEIVED) {
            goto AGAIN;
        }
        errorf("open error: %d", pcb->state);
        pcb->state = TCP_PCB_STATE_CLOSED;
        tcp_pcb_release(pcb);
        mutex_unlock(&mutex);
        return -1;
    }
    id = tcp_pcb_id(pcb);
    debugf("connection established: local=%s, foreign=%s",
        ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)),
        ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    mutex_unlock(&mutex);
    return id;
}

int tcp_close(int id) {
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
    switch (pcb->state) {
        case TCP_PCB_STATE_ESTABLISHED:
            tcp_output(pcb, TCP_FLG_ACK | TCP_FLG_FIN, NULL, 0);
            pcb->state = TCP_PCB_STATE_FIN_WAIT1;
            pcb->snd.nxt++;
            break;
        case TCP_PCB_STATE_CLOSE_WAIT:
            tcp_output(pcb, TCP_FLG_ACK | TCP_FLG_FIN, NULL, 0);
            pcb->state = TCP_PCB_STATE_LAST_ACK;
            pcb->snd.nxt++;
            break;
        default:
            errorf("unknown state '%u'", pcb->state);
            mutex_unlock(&mutex);
            return -1;
    }
    sched_wakeup(&pcb->ctx);
    mutex_unlock(&mutex);
    return 0;
}

ssize_t tcp_send(int id, uint8_t *data, size_t len) {
    struct tcp_pcb *pcb;
    ssize_t sent = 0;
    struct ip_iface *iface;
    size_t mss, cap, slen;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
RETRY:
    switch (pcb->state) {
        case TCP_PCB_STATE_ESTABLISHED:
        case TCP_PCB_STATE_CLOSE_WAIT: // まだ送信したいデータがあればユーザーがsendtoと使用する
            // 送信に使われるインタフェースを取得
            iface = ip_route_get_iface(pcb->foreign.addr);
            if (!iface) {
                errorf("iface not found");
                mutex_unlock(&mutex);
                return -1;
            }
            // MSS(Max Segment Size)を計算
            mss = NET_IFACE(iface)->dev->mtu - (IP_HDR_SIZE_MIN + sizeof(struct tcp_hdr));
            while (sent < (ssize_t)len) {
                // 相手がpcb->bufからbufに取り出してないサイズを引く
                cap = pcb->snd.wnd - (pcb->snd.nxt - pcb->snd.una);
                if (!cap) {
                    if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
                        debugf("interrupted");
                        if (!sent) {
                            mutex_unlock(&mutex);
                            errno = EINTR;
                            return -1;
                        }
                        break;
                    }
                    goto RETRY;
                }
                slen = MIN(MIN(mss, len - sent), cap);
                if (tcp_output(pcb, TCP_FLG_ACK | TCP_FLG_PSH, data + sent, slen) == -1) {
                    errorf("tcp_output() failure");
                    pcb->state = TCP_PCB_STATE_CLOSED;
                    tcp_pcb_release(pcb);
                    mutex_unlock(&mutex);
                    return -1;
                }
                pcb->snd.nxt += slen;
                sent += slen;
            }
            break;
        case TCP_PCB_STATE_LAST_ACK:
            errorf("connection closing");
            mutex_unlock(&mutex);
            return -1;
        default:
            errorf("unknown state '%u'", pcb->state);
            mutex_unlock(&mutex);
            return -1;
    }
    mutex_unlock(&mutex);
    return sent;
}

ssize_t tcp_receive(int id, uint8_t *buf, size_t size) {
    struct tcp_pcb *pcb;
    size_t remain, len;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
RETRY_RECEIVE:
    switch (pcb->state) {
        case TCP_PCB_STATE_ESTABLISHED:
            remain = sizeof(pcb->buf) - pcb->rcv.wnd;
            // 受信バッファにデータが格納されるまで待機
            if (!remain) {
                if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
                    debugf("interrupted");
                    mutex_unlock(&mutex);
                    errno = EINTR;
                    return -1;
                }
                goto RETRY_RECEIVE;
            }
            break;
        case TCP_PCB_STATE_CLOSE_WAIT:
            remain = sizeof(pcb->buf) - pcb->rcv.wnd;
            if (remain) break;
            debugf("connection closing");
            mutex_unlock(&mutex);
            return 0;
        default:
            errorf("unknown state '%u'", pcb->state);
            mutex_unlock(&mutex);
            return -1;
    }
    // bufに収まる分だけコピー
    len = MIN(size, remain);
    memcpy(buf, pcb->buf, len);
    infof("-------------------------------len=%d", len);
    // コピー済みのデータをバッファから消す
    memmove(pcb->buf, pcb->buf + len, remain - len);
    pcb->rcv.wnd += len;
    mutex_unlock(&mutex);
    return len;
}
