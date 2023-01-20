#include <stdio.h>
#include <stdint.h>
#include <stddef.h> // NULL offsetof
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"
#include "arp.h"

// IPヘッダを表現するための構造体
// この構造体にキャストすることでバイト列をIPヘッダと見なしてアクセスできる
struct ip_hdr {
    uint8_t vhl; // バージョン(4bit)とIPヘッダ長(4bit)をまとめて8bitとして扱う
    uint8_t tos;
    uint16_t total;
    uint16_t id;
    uint16_t offset; // フラグ(3bit)とフラグメントオフセット(13bit)をまとめて16bitとして扱う
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum;
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[]; // オプション（可変長なのでフレキシブル配列メンバとする）
};

// IPの上位プロトコルを管理するための構造体
// struct net_protocolとほぼ同じ（受信キューがない分シンプル）
struct ip_protocol {
    struct ip_protocol *next;
    uint8_t type;
    void (*handler)(const uint8_t *data, size_t len, ip_addr_t str, ip_addr_t dst, struct ip_iface *iface);
};

// 経路情報の構造体（リストで管理）
struct ip_route {
    struct ip_route *next;  // 次の経路情報へのポインタ
    ip_addr_t network;      // ネットワークアドレス
    ip_addr_t netmask;      // サブネットマスク
    ip_addr_t nexthop;      // 次の中継先アドレス（なければIP_ADDR_ANY）
    struct ip_iface *iface; // この経路への送信に使うインタフェース
};

const ip_addr_t IP_ADDR_ANY       = 0x00000000; /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex */
static struct ip_iface *ifaces;
static struct ip_protocol *protocols; // 登録されているプロトコルのリスト（グローバル変数）
static struct ip_route *routes;       // 経路情報のリスト（ルーティングテーブル）

// IPアドレスを文字列からネットワークバイトオーダーのバイナリ値(ip_addr_t)に変換
int ip_addr_pton(const char *p, ip_addr_t *n) {
    char *sp, *ep;
    long ret;

    sp = (char *)p;
    for (int idx = 0; idx < 4; idx++) {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255)
            return -1;
        if (ep == sp) 
            return -1;
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.'))
            return -1;
        ((uint8_t *)n)[idx] = ret;    
        sp = ep + 1;
    }
    return 0;
}

// IPアドレスをネットワークバイトオーダーのバイナリ値(ip_addr_t)から文字列に変換
char *ip_addr_ntop(ip_addr_t n, char *p, size_t size) {
    uint8_t *u8;

    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

int ip_endpoint_pton(const char *p, struct ip_endpoint *n) {
    char *sep;
    char addr[IP_ADDR_STR_LEN] = {};
    long int port;

    sep = strrchr(p, ':');
    if (!sep) 
        return -1;
    memcpy(addr, p, sep - p);
    if (ip_addr_pton(addr, &n->addr) == -1)
        return -1;
    port = strtol(sep+1, NULL, 10);
    if (port <= 0 || port > UINT16_MAX)
        return -1;
    n->port = hton16(port);
    return 0;
}

char *ip_endpoint_ntop(const struct ip_endpoint *n, char *p, size_t size) {
    size_t offset;

    ip_addr_ntop(n->addr, p, size);
    offset = strlen(p);
    snprintf(p + offset, size - offset, ":%d", ntoh16(n->port));
    return p;
}

static void ip_dump(const uint8_t *data, size_t len) {
    struct ip_hdr *hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip_hdr *)data;
    v = (hdr->vhl & 0xf0) >> 4; // version(4bit)
    hl = hdr->vhl & 0x0f; // IHL IPヘッダ長(4bit)
    hlen = hl << 2; // IPヘッダ長...32bit(4byte)単位の値が格納されているので4倍して8bit(1byte)単位の値にする
    fprintf(stderr, "        vhl: 0x%02x [v: %u, hl:%u (%u)]\n", hdr->vhl, v, hl, hlen);
    fprintf(stderr, "        tos: 0x%02x\n", hdr->tos);

    total = ntoh16(hdr->total); // 多バイト長(16bitや32bit)の数値データはバイトオーダーの変換が必要
    fprintf(stderr, "      total: %u (payload %u)\n", total, total - hlen); // トータル長からIPヘッダ長を引いたものが運んでいるデータ（ペイロード）
    fprintf(stderr, "         id: %u\n", ntoh16(hdr->id));

    offset = ntoh16(hdr->offset);
    fprintf(stderr, "     offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff); // offset...上位3bit=フラグ, 下位13bit = フラグメントオフセット
    fprintf(stderr, "        ttl: %u\n", hdr->ttl);
    fprintf(stderr, "   protocol: %u\n", hdr->protocol);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "        src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr))); // IPアドレスをネットワークバイトオーダーのバイナリ値(ip_addr_t)から文字列に変換
    fprintf(stderr, "        dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));

#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/* NOTE: must not be call after net_run() */
static struct ip_route *ip_route_add(ip_addr_t network, ip_addr_t netmask, ip_addr_t nexthop, struct ip_iface *iface) {
    struct ip_route *route;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];
    char addr4[IP_ADDR_STR_LEN];

    // 経路情報の登録
    // ・新しい経路情報を作成してルーティングテーブルへ追加する（必要な情報は全て引数で受けっている）
    route = memory_alloc(sizeof(*route));
    if (!route) {
        errorf("memory_alloc() failure");
        return NULL;
    }

    route->network = network;
    route->netmask = netmask;
    route->nexthop = nexthop;
    route->iface = iface;
    route->next = routes;
    routes = route;
    infof("route added: network=%s, netmask=%s, nethop=%s, iface=%s, dev=%s, route=%x",
        ip_addr_ntop(route->network, addr1, sizeof(addr1)),
        ip_addr_ntop(route->netmask, addr2, sizeof(addr2)),
        ip_addr_ntop(route->nexthop, addr3, sizeof(addr3)),
        ip_addr_ntop(route->iface->unicast, addr4, sizeof(addr4)),
        NET_IFACE(iface)->dev->name,
        route);
    return route;
}

// 経路情報の探索
static struct ip_route *ip_route_lookup(ip_addr_t dst) {
    struct ip_route *route, *candidate = NULL;
    char addr1[IP_ADDR_STR_LEN];

    // ルーティングテーブルを巡回
    for (route = routes; route; route = route->next) {
        // 宛先が経路情報のネットワークに含まれているか確認
        if ((dst & route->netmask) == (route->network & route->netmask)) {
            // サブネットマスクがより長く一致する経路を選択する（ロンゲストマッチ）
            // 長く一致する方がより詳細な経路情報となる
            if (!candidate || ntoh32(candidate->netmask) < ntoh32(route->netmask)) {
                candidate = route;
            }
        }
    }

    infof("candidate: network: %s", ip_addr_ntop(candidate->network, addr1, sizeof(addr1)));
    return candidate;
}

/* NOTE: must not be call after net_run() */
// デフォルトゲートウェイの登録
int ip_route_set_default_gateway(struct ip_iface *iface, const char *gateway) {
    ip_addr_t gw;

    // デフォルトゲートウェイのIPアドレスを文字列からバイナリ値へ変換
    if (ip_addr_pton(gateway, &gw) == -1) {
        errorf("ip_addr_pton() failure, addr=%s", gateway);
        return -1;
    }

    // 0.0.0.0/0のサブネットワークへの経路情報として登録する
    if (!ip_route_add(IP_ADDR_ANY, IP_ADDR_ANY, gw, iface)) {
        errorf("ip_route_add() falure");
        return -1;
    }
    return 0;
}

struct ip_iface *ip_route_get_iface(ip_addr_t dst) {
    struct ip_route *route;

    route = ip_route_lookup(dst);
    if (!route) 
        return NULL;
    return route->iface;
}

struct ip_iface *ip_iface_alloc(const char *unicast, const char *netmask) {
    struct ip_iface *iface;

    iface = memory_alloc(sizeof(*iface));
    if (!iface) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    // インタフェースの種別を示すfamilyの値の設定
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;

    // IPインタフェースにアドレス情報を設定

    // 引数unicastを文字列からバイナリ値へ変換して設定する
    if (ip_addr_pton(unicast, &(iface->unicast)) == -1) {
        memory_free(iface);
        errorf("ip_addr_pton() failure");
        return NULL;
    }

    // netmaskを文字列からバイナリ値への変換して設定する
    if (ip_addr_pton(netmask, &(iface->netmask)) == -1) {
        memory_free(iface);
        errorf("ip_addr_pton(netmask, &(iface->netmask)) failure");
        return NULL;
    }

    // iface->broadcast: iface->unicastとiface->netmaskの値から産出して設定する
    iface->broadcast = (iface->unicast & iface->netmask) | (~iface->netmask);

    return iface;
}

/* NOTE: must not be call after net_run() */
int ip_iface_register(struct net_device *dev, struct ip_iface *iface) {
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];

    // IPインタフェースの登録
    
    // デバイスにIPインタフェース(iface)を登録する
    // エラーが返されたらこの関数もエラーを返す
    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1) {
        errorf("net_device_add_iface() failure");
        return -1;
    }

    // インタフェース登録時にそのネットワーク宛の経路情報を自動で登録する
    // とりあえず未設定(0.0.0.0)を設定
    if (!ip_route_add(iface->unicast, iface->netmask, IP_ADDR_ANY, iface)) {
        errorf("ip_route_add() failure");
        return -1;
    }

    // IPインタフェースのリスト(ifaces)の先頭にifaceを挿入する
    iface->next = ifaces;
    ifaces = iface;

    infof("registered: dev=%s, unicast=%s, netmask=%s, breadcast=%s", dev->name,
        ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)), 
        ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)), 
        ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));
    return 0;
}

struct ip_iface *ip_iface_select(ip_addr_t addr) {
    // IPインタフェースの検索
    // 引数addrで指定されたIPアドレスを持つインタフェースを返す
    // 合致するインタフェースを発見できなかったらNULLを返す
    struct ip_iface *iface;

    for (iface = ifaces; iface; iface = iface->next) {
        if (iface->unicast == addr)
            return iface;
    }
    return NULL;
}

/* NOTE: must not be call after net_run() */
int ip_protocol_register(uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)) {
    struct ip_protocol *entry;

    // 重複登録の確認
    // プロトコルリスト(protocols)を巡回
    // 指定されたtypeのエントリが既に存在する場合はエラーを返す
    for (entry = protocols; entry; entry = entry->next) {
        if (entry->type == type) {
            return -1;
        }
    }

    // プロトコルの登録
    // 新しいプロトコルのエントリようにメモリを確保
    // 新しいプロトコルのエントリに値を設定
    // プロトコルリスト(protocols)の先頭に挿入
    entry = memory_alloc(sizeof(struct ip_protocol));
    if (!entry) {
        return -1;
    }
    entry->type = type;
    entry->handler = handler;
    entry->next = protocols;
    protocols = entry;

    infof("registered, type=%u", entry->type);
    return 0;
}

static void ip_input(const uint8_t *data, size_t len, struct net_device *dev) {
    struct ip_hdr *hdr;
    uint8_t v;
    uint16_t hlen, total, offset;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];

    // 入力データの長さがIPヘッダの最小サイズより小さい場合はエラー
    if (len < IP_HDR_SIZE_MIN) {
        errorf("too short");
        return;
    }

    hdr = (struct ip_hdr *)data;

    // バージョンチェック
    v = (hdr->vhl & 0xf0) >> 4;
    if (v != IP_VERSION_IPV4) {
        errorf("version error");
        return;
    }

    // ヘッダ長チェック
    hlen = (hdr->vhl & 0x0f) << 2;
    if (hlen > len) {
        errorf("head length too short");
        return;
    }

    // トータル長のチェック
    total = ntoh16(hdr->total);
    if (total > len) {
        errorf("total length too short");
        return;
    }

    // チェックサム
    if (cksum16((uint16_t *)hdr, hlen, 0)) {
        errorf("error checksum");
        return;
    }

    // 今回はIPのフラグメントをサポートしないのでフラグメントだったら処理せず中断する
    // フラグメントかどうかの判断...MF(More Flagments)ビットが立っている or フラグメントオフセットに値がある
    offset = ntoh16(hdr->offset);
    if (offset & 0x2000 || offset & 0x1fff) {
        errorf("fragment does not support");
        return;
    }

    // IPデータグラムのフィルタリング
    
    // デバイスに紐づくIPインタフェースを取得
    // IPインタフェースを取得できなかったら中断する
    if (dev->ifaces)
        iface = (struct ip_iface *)dev->ifaces;
    else
        return;
    
    // 宛先IPアドレスの検証
    // 以下のいずれにも一致しない場合は「他ホスト宛」と判断して中断する（エラーメッセージは出力しない）
    if (hdr->dst != IP_ADDR_BROADCAST) {
        for (; iface; iface = iface->next) {
            if (iface->broadcast == hdr->dst || iface->unicast == hdr->dst)
                break;
        }
    }
    if (!iface)
        return;

    debugf("dev=%s, iface=%s, protocol=%u, total=%u", dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol, total);
    ip_dump(data, total);


    // 上位プロトコルへのデータの振り分け

    // プロトコルの検索
    // プロトコルリスト(protocols)を巡回
    // IPヘッダのプロトコル番号と一致するプロトコルの入力関数を呼び出す（入力関数にはIPデータグラムのペイロードを渡す）
    // 入力関数から戻ったらreturnする
    // 合致するプロトコルが見つからない場合は何もしない
    struct ip_protocol *entry;
    for (entry = protocols; entry; entry = entry->next) {
        if (entry->type == hdr->protocol) {
            entry->handler((uint8_t *)hdr + hlen, total - hlen, hdr->src, hdr->dst, iface);
            return;
        }
    }
    /* unsupported protocol */
}

static int ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst) {
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};
    int ret;
    
    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP) { // ARPによるアドレス解決が必要なデバイスのための処理
        
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
            // 宛先がブロードキャストIPアドレスの場合にはARPによるアドレス解決は行わず
            // そのデバイスのブロードキャストHWアドレスを使う
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
        } else {
            // ユニキャストなら相手のMACアドレスを知っているか確認する

            // arp_resolve()を呼び出してアドレスを解決する
            // 戻り値がARPRESOLVE_FOUNDでなかったらその値をこの関数の戻り値として返す
            ret = arp_resolve(NET_IFACE(iface), dst, hwaddr);
            if (ret != ARP_RESOLVE_FOUND) {
                return ret;
            }
        }
    }

    // デバイスから送信
    // net_device_output()を呼び出してインタフェースに紐づくデバイスからIPデータグラムを送信
    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, hwaddr);
}

// IPデータグラムを生成
static ssize_t ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, ip_addr_t nexthop, uint16_t id, uint16_t offset) {
    uint8_t buf[IP_TOTAL_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t hlen, total;
    char addr[IP_ADDR_STR_LEN];

    hdr = (struct ip_hdr *) buf;

    // IPデータグラムの生成
    
    // IPヘッダの各フィールドに値を設定
    // IPヘッダの長さはIP_HDR_SIZE_MINを固定とする（オプションなし）
    // TOS=0, TTL=255とする
    // チェックサムの計算結果はバイトオーダーを変更せずにそのまま設定する（ネットワークバイトオーダーのバイト列のチェックサム計算結果はネットワークバイトオーダーで得られる）
    // チェックサム計算の際、あらかじめチェックサムフィールドに0を設定するのを忘れずに
    hlen = sizeof(*hdr);
    total = hlen + len;
    hdr->vhl = (IP_VERSION_IPV4 << 4) | (hlen >> 2);
    hdr->tos = 0;
    hdr->total = hton16(total);
    hdr->id = hton16(id);
    hdr->offset = hton16(offset);
    hdr->ttl = 0xff;
    hdr->protocol = protocol;
    hdr->sum = 0;
    hdr->src = src;
    hdr->dst = dst;
    hdr->sum = cksum16((uint16_t *)hdr, hlen, 0);

    // IPヘッダの直後にデータを配置する
    memcpy(hdr+1, data, len);

    debugf("dev=%s, dst=%s, protocol=%u, len=%u", NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
    ip_dump(buf, total);

    // 生成したIPデータグラムを実際にデバイスから送信するための関数に渡す
    return ip_output_device(iface, buf, total, nexthop);
}

static uint16_t ip_generate_id(void) {
    static mutex_t mutex = MUTEX_INITIALIZER;
    static uint16_t id = 128;
    uint16_t ret;

    mutex_lock(&mutex);
    ret = id++;
    mutex_unlock(&mutex);

    return ret;
}

ssize_t ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst) {
    struct ip_route *route;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    ip_addr_t nexthop;
    uint16_t id;
    
    // 送信元アドレスが指定されていない場合、ブロードキャストアドレスあてへの送信はできない
    if (src == IP_ADDR_ANY && dst == IP_ADDR_BROADCAST) {
        errorf("ip routing does not implement");
        return -1;
    } 

    // 宛先アドレスへの経路情報を取得
    route = ip_route_lookup(dst);
    if (!route) {
        errorf("no route to host, addr=%s", ip_addr_ntop(dst, addr, sizeof(addr)));
        return -1;
    }
    
    // インタフェースのIPアドレスと異なるIPアドレスで
    // 送信できないように制限（強いエンドシステム）
    iface = route->iface;
    if (src != IP_ADDR_ANY && src != iface->unicast) {
        errorf("unable to output with specified source address, addr=%s", ip_addr_ntop(src, addr, sizeof(addr)));
        return -1;
    }

    // nexthop ... IPパケットの次の送り先（IPヘッダの宛先とは異なる）
    nexthop = (route->nexthop != IP_ADDR_ANY)? route->nexthop: dst;

    // フラグメンテーションをサポートしないのでＭＴＵを超える場合はエラーを返す
    if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len) {
        errorf("too long, dev=%s, mtu=%u < %zu", NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }

    // IPデータグラムのIDを採番
    id = ip_generate_id();
    
    // IPデータグラムを生成して出力するための関数を呼ぶ
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, nexthop, id, 0) == -1) {
        errorf("ip_output_core() failure");
        return -1;
    }
    return len;
}

int ip_init(void) {
    // プロトコルスタックにIPの入力関数を登録する
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}