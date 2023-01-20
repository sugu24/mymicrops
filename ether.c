#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "util.h"
#include "net.h"
#include "ether.h"

// Ethernetヘッダの構造体
struct ether_hdr {
    uint8_t dst[ETHER_ADDR_LEN];
    uint8_t src[ETHER_ADDR_LEN];
    uint16_t type;
};

const uint8_t ETHER_ADDR_ANY[ETHER_ADDR_LEN] = {"\x00\x00\x00\x00\x00\x00"};
const uint8_t ETHER_ADDR_BROADCAST[ETHER_ADDR_LEN] = {"\xff\xff\xff\xff\xff\xff"};

int ether_addr_pton(const char *p, uint8_t *n) {
    int index;
    char *ep;
    long val;

    if (!p || !n) return -1;

    for (index = 0; index < ETHER_ADDR_LEN; index++) {
        val = strtol(p, &ep, 16);
        if (ep == p || val < 0 || val > 0xff || (index < ETHER_ADDR_LEN - 1 && *ep != ':')) {
            break;
        }
        n[index] = (uint8_t)val;
        p = ep + 1;
    }
    if (index != ETHER_ADDR_LEN || *ep != '\0')
        return -1;
    return 0;
}

char *ether_addr_ntop(const uint8_t *n, char *p, size_t size) {
    if (!n || !p)
        return NULL;
    
    snprintf(p, size, "%02x:%02x:%02x:%02x:%02x:%02x", n[0], n[1], n[2], n[3], n[4], n[5]);
    return p;
}

static void ether_dump(const uint8_t *frame, size_t flen) {
    struct ether_hdr *hdr;
    char addr[ETHER_ADDR_STR_LEN];

    hdr = (struct ether_hdr *)frame;
    flockfile(stderr);
    fprintf(stderr, "    src: %s\n", ether_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "    dst: %s\n", ether_addr_ntop(hdr->dst, addr, sizeof(addr)));
    fprintf(stderr, "   type: 0x%04x\n", ntoh16(hdr->type));
#ifdef HEXDUMP
    hexdump(stderr, frame, flen);
#endif
    funlockfile(stderr);
}

// Ethernetフレームの生成と出力
int ether_transmit_helper(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst, ether_transmit_func_t callback) {
    uint8_t frame[ETHER_FRAME_SIZE_MAX] = {};
    struct ether_hdr *hdr;
    size_t flen, pad = 0;

    // Etherフレームの生成
    // ヘッダの各フィールドに値を設定
    // ヘッダの直後にデータをコピー
    hdr = (struct ether_hdr *) frame;
    memcpy(hdr->dst, dst, ETHER_ADDR_LEN);
    memcpy(hdr->src, dev->addr, ETHER_ADDR_LEN);
    hdr->type = hton16(type);
    memcpy(hdr+1, data, len);

    // 最小サイズに満たない場合はパディングして挿入してサイズを調整
    if (len < ETHER_PAYLOAD_SIZE_MIN)
        pad = ETHER_PAYLOAD_SIZE_MIN - len;
    flen = sizeof(*hdr) + len + pad;
    
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, flen);
    ether_dump(frame, flen);

    // 引数で渡された関数をコールバックして生成したEthernetフレームを出力する
    // 実際の書き込み処理はether_input_helper()を呼び出したドライバの関数の中で行われる
    return callback(dev, frame, flen) == (ssize_t)flen ? 0: -1;
}

// Ethernetフレームの入力と検証
int ether_input_helper(struct net_device *dev, ether_input_func_t callback) {
    uint8_t frame[ETHER_FRAME_SIZE_MAX];
    ssize_t flen;
    struct ether_hdr *hdr;
    uint16_t type;

    // 引数で渡された関数をコールバックしてEthernetフレームを読み込む
    // 実際の読み込みはether_input_helper()をよびだしたドライバの関数の中で行われ、ether_input_helper()は結果だけ受け取る
    flen = callback(dev, frame, sizeof(frame));

    // 読み込んだフレームのサイズEthernetヘッダより小さかったらエラーとする
    if (flen < (ssize_t)sizeof(*hdr)) {
        errorf("too short");
        return -1;
    }

    hdr = (struct ether_hdr *)frame;

    // Ethernetフレームのフィルタリング
    // 宛先がデバイス自身のMACアドレスまたはブロードキャストMACアドレスであればOK
    // それ以外は他のホストあてと見なして黙って破棄する
    if (memcmp(dev->addr, hdr->dst, ETHER_ADDR_LEN) != 0) {
        if (memcmp(ETHER_ADDR_BROADCAST, hdr->dst, ETHER_ADDR_LEN) != 0) {
            // for other host
            return -1;
        }
    }
    
    type = ntoh16(hdr->type);
    debugf("dev=%s, type=0x%04x, len=%zd", dev->name, type, flen);
    ether_dump(frame, flen);

    // net_input_handler()を呼び出してプロトコルスタックにペイロードを渡す
    return net_input_handler(type, (uint8_t *)(hdr+1), flen - sizeof(*hdr), dev);
}

// Ethernetデバイスの共通設定
void ether_setup_helper(struct net_device *dev) {
    dev->type = NET_DEVICE_TYPE_ETHERNET;
    dev->mtu = ETHER_PAYLOAD_SIZE_MAX;
    dev->flags = (NET_DEVICE_FLAG_BROADCAST | NET_DEVICE_FLAG_NEED_ARP);
    dev->hlen = ETHER_HDR_SIZE;
    dev->alen = ETHER_ADDR_LEN;
    memcpy(dev->broadcast, ETHER_ADDR_BROADCAST, ETHER_ADDR_LEN);
}
