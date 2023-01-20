#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

// ハードウェアアドレス種別とプロトコルアドレス種別の定数
/* see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt */
#define ARP_HDR_ETHER 0x0001

/* NOTE: use same value as the Ethernet types */
#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

#define ARP_CACHE_SIZE 32
#define ARP_CACHE_TIMEOUT 30 // seconds

// ARPキャッシュの状態を表す定数
#define ARP_CACHE_STATE_FREE       0
#define ARP_CACHE_STATE_INCOMPLETE 1
#define ARP_CACHE_STATE_RESOLVED   2
#define ARP_CACHE_STATE_STATIC     3

// ARPヘッダの構造体
struct arp_hdr {
    uint16_t hdr;
    uint16_t pro;
    uint8_t hln;
    uint8_t pln;
    uint16_t op;
};

// Ethernet/IP ペアのためのARPメッセージ構造体
// spa(tpa)をip_addr_tにするとsha(tha)との間にパディングが挿入されてしまうので注意
// アラインメント処理によって32bit幅の変数は4の倍数のアドレスに配置するよう調整されてしまう
struct arp_ether_ip {
    struct arp_hdr hdr;
    uint8_t sha[ETHER_ADDR_LEN]; // ハードウェアアドレス(Ethernetアドレス (MACアドレス))
    uint8_t spa[IP_ADDR_LEN];    // プロトコルアドレス(IPアドレス)
    uint8_t tha[ETHER_ADDR_LEN]; // ハードウェアアドレス(Ethernetアドレス (MACアドレス))
    uint8_t tpa[IP_ADDR_LEN];    // プロトコルアドレス(IPアドレス)
};

// ARPキャッシュの構造体
struct arp_cache {
    unsigned char state;        // キャッシュの状態
    ip_addr_t pa;               // プロトコルアドレス, IPアドレス
    uint8_t ha[ETHER_ADDR_LEN]; // ハードウェアアドレス
    struct timeval timestamp;   // 最終更新時刻
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct arp_cache caches[ARP_CACHE_SIZE]; // ARPキャッシュの配列（ARPテーブル）

static char *arp_opcode_ntoa(uint16_t opcode) {
    switch (ntoh16(opcode)) {
        case ARP_OP_REQUEST:
            return "Request";
        case ARP_OP_REPLY:
            return "Reply";
    }
    return "Unknown";
}

static void arp_dump(const uint8_t *data, size_t len) {
    struct arp_ether_ip *message;
    ip_addr_t spa, tpa;
    char addr[128];

    // ここではEthernet/IPペアのメッセージと見なす
    message = (struct arp_ether_ip *)data;

    flockfile(stderr);
    fprintf(stderr, "    hdr: 0x%04x\n", ntoh16(message->hdr.hdr));
    fprintf(stderr, "    pro: 0x%04x\n", ntoh16(message->hdr.pro));
    fprintf(stderr, "    hln: %u\n", message->hdr.hln);
    fprintf(stderr, "    pln: %u\n", message->hdr.pln);
    fprintf(stderr, "     op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
    fprintf(stderr, "    sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
    // spaがuint8_t[4]なので、いったんmemcpy()でip_addr_tの変数へ取り出す
    memcpy(&spa, message->spa, sizeof(spa));
    fprintf(stderr, "    spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
    fprintf(stderr, "    tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
    // tpaも同様にmemcpy()でip_addr_tの変数へ取り出す
    memcpy(&tpa, message->tpa, sizeof(tpa));
    fprintf(stderr, "    tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
    ARP Cache
    NOTE: ARP Cache functions must be called after mutex locked
*/

static void arp_cache_delete(struct arp_cache *cache) {
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    debugf("DELETE: pa=%s, ha=%s", ip_addr_ntop(cache->pa, addr1, sizeof(addr1)), ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));

    // キャッシュのエントリを削除する
    // stateは未使用（FREE）の状態にする
    // 各フィールドを0にする
    // timestampはtimerclear()でクリアする
    cache->state = ARP_CACHE_STATE_FREE;
    cache->pa = 0;
    cache->ha[0] = '\0';
    timerclear(&(cache->timestamp));
}

static struct arp_cache *arp_cache_alloc(void) {
    struct arp_cache *entry, *oldest = NULL;

    for (entry = caches; entry < tailof(caches); entry++) {
        // ARPキャッシュのテーブルを巡回

        // 使用されていないエントリを返す
        if (entry->state == ARP_CACHE_STATE_FREE)
            return entry;

        // 空きがなかったときのために一番古いエントリも一緒に探す
        if (!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >))
            oldest = entry;
    }
    arp_cache_delete(oldest);
    return oldest;
}

static struct arp_cache *arp_cache_select(ip_addr_t pa) {
    struct arp_cache *entry;
    // キャッシュの中からプロトコルアドレスが一致するエントリを探して返す
    // 念のためFREE状態ではないエントリの中から探す
    // 見つからなかったらNULLを返す
    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state != ARP_CACHE_STATE_FREE && entry->pa == pa) 
            return entry;
    }
    return NULL;
}

static struct arp_cache *arp_cache_update(ip_addr_t pa, const uint8_t *ha) {
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    // キャッシュに登録されている情報を更新する

    // arp_cache_select()でエントリを検索する
    // 見つからなかったらエラー（NULL）を返す
    cache = arp_cache_select(pa);
    if (!cache)
        return NULL;
    
    // エントリの情報を更新する
    // stateは解決済み（RESOLVE）の状態にする
    // timestampはgettimeofday()で設定する
    cache->state = ARP_CACHE_STATE_RESOLVED;
    cache->pa = pa;
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    gettimeofday(&(cache->timestamp), NULL);

    debugf("UPDATE: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return cache;
}

// ARPキャッシュの登録
static struct arp_cache *arp_cache_insert(ip_addr_t pa, const uint8_t *ha) {
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    // キャッシュに新しくエントリを登録する

    // arp_cache_alloc()でエントリの登録スペースを確保する
    cache = arp_cache_alloc();
    if (!cache) {
        errorf("arp_cache_alloc() failure");
        return NULL;
    }

    // エントリの情報を設定する
    // stateは解決済み（RESOLVED）の状態にする
    // timestampはgettimeofday()で設定する
    cache->state = ARP_CACHE_STATE_RESOLVED;
    cache->pa = pa;
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    gettimeofday(&(cache->timestamp), NULL);

    debugf("INSERT: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return cache;
}

// ARP要求の送信関数
static int arp_request(struct net_iface *iface, ip_addr_t tpa) {
    struct arp_ether_ip request;

    request.hdr.hdr = ntoh16(ARP_HDR_ETHER);
    request.hdr.pro = ntoh16(ARP_PRO_IP);
    request.hdr.hln = ETHER_ADDR_LEN;
    request.hdr.pln = IP_ADDR_LEN;
    request.hdr.op = ntoh16(ARP_OP_REQUEST);

    memcpy(request.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(request.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    // memcpy(request.tha, 0, ETHER_ADDR_LEN);
    memcpy(request.tpa, &tpa, IP_ADDR_LEN);

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(request));
    arp_dump((uint8_t *)&request, sizeof(request));

    // デバイスの送信関数を呼び出してARP要求のメッセージを送信する
    // 宛先はデバイスに設定されているブロードキャストアドレスとする
    // デバイスの送信関数の戻り値をこの関数の戻り値とする
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&request, sizeof(request), iface->dev->broadcast);
}

// ARP応答の送信
static int arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst) {
    struct arp_ether_ip reply;

    // ARP応答メッセージの生成
    // spa/sha ... インタフェースのIPアドレスと紐づくデバイスのMACアドレスを設定する
    // tpa/tha ... ARP要求を送ってきたノードのIPアドレスとMACアドレスを設定する
    reply.hdr.hdr = ntoh16(ARP_HDR_ETHER);
    reply.hdr.pro = ntoh16(ARP_PRO_IP);
    reply.hdr.hln = ETHER_ADDR_LEN;
    reply.hdr.pln = IP_ADDR_LEN;
    reply.hdr.op = ntoh16(ARP_OP_REPLY);

    memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    memcpy(reply.tha, tha, ETHER_ADDR_LEN);
    memcpy(reply.tpa, &tpa, IP_ADDR_LEN);

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(reply));
    arp_dump((uint8_t *)&reply, sizeof(reply));

    // デバイスからARPメッセージを送信する
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst);
}

static void arp_input(const uint8_t *data, size_t len, struct net_device *dev) {
    struct arp_ether_ip *msg;
    ip_addr_t spa, tpa;
    struct net_iface *iface;

    // 更新の可否を示すグラフ
    int merge = 0;

    // 期待するARPメッセージのサイズより小さかったらエラーを返す
    if (len < sizeof(*msg)) {
        errorf("too short");
        return;
    }
    msg = (struct arp_ether_ip *)data;

    // 対応可能なアドレスペアのメッセージのみ受け取る
    
    // ハードウェアアドレスのチェック
    // アドレス種別とアドレス長がEthernetと一致しなければ中断する
    if (ntoh16(msg->hdr.hdr) != ARP_HDR_ETHER || msg->hdr.hln != ETHER_ADDR_LEN) {
        errorf("unsupported hardware address");
        return;
    }
    
    // プロトコルアドレスのチェック
    // アドレス種別とアドレス帳がIPと合致しなければ終了
    if (ntoh16(msg->hdr.pro) != ARP_PRO_IP || msg->hdr.pln != IP_ADDR_LEN) {
        errorf("unsupported protocol address");
        return;
    }
    
    debugf("dev=%s, len=%zu", dev->name, len);
    arp_dump(data, len);

    // spa/tpaをmemcpy()でip_addr_tの変数へ取り出す
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));

    // キャッシュへのアクセスをミューテックスで保護
    mutex_lock(&mutex);

    // ARPメッセージを受信したら、まず送信元アドレスのキャッシュ情報を更新する（更新なので未登録の場合には失敗する）
    if (arp_cache_update(spa, msg->sha)) {
        /* updated */
        merge = 1;
    }

    // アンロックを忘れずに
    mutex_unlock(&mutex);

    // デバイスに紐づくIPインタフェースを取得する
    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);

    // ARP要求のターゲットプロトコルアドレスと一致するか確認
    if (iface && ((struct ip_iface *)iface)->unicast == tpa) {
        // 先の処理で送信元アドレスのキャッシュ情報が更新されていなかったら（まだ未登録だったら）
        if (!merge) {
            mutex_lock(&mutex);
            infof("merge arp cache");
            arp_cache_insert(spa, msg->sha);
            mutex_unlock(&mutex);
        }
        
        // ARP要求への応答
        // メッセージ種別がARP要求だったらarp_reply()を呼び出してARP応答を送信する
        if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST)
            arp_reply(iface, msg->sha, spa, msg->sha);
    }
}

// アドレス解決を実行する関数
// アドレスをキャッシュに記憶させる
int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha) {
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    // 念のため、物理デバイスと論理インタフェースがそれぞれEthernetとIPv4であることを確認
    if (iface->dev->type != NET_DEVICE_TYPE_ETHERNET) {
        debugf("unsupported hardware address type");
        return ARP_RESOLVE_ERROR;
    }
    if (iface->family != NET_IFACE_FAMILY_IP) {
        debugf("unsupported protocol address type");
        return ARP_RESOLVE_ERROR;
    }

    // ARPキャッシュへのアクセスをmutexで保護
    mutex_lock(&mutex);

    // ARPキャッシュを検索（キー：プロトコルアドレス）
    cache = arp_cache_select(pa);
    if (!cache) {
        debugf("cache not found, pa=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)));
        // ARPキャッシュに問い合わせ中のエントリを作成
        
        // 新しいエントリの領域を確保
        // 領域を確保できなかったらERRORを返す
        cache = arp_cache_alloc();
        if (!cache) {
            errorf("arp_cache_alloc() failure");
            return ARP_RESOLVE_ERROR;
        }

        // エントリの各フィールドに値を設定する
        // state:INCOMPLETE
        // pa:引数で受け取ったプロトコルアドレス
        // ha:未設定（なにもしない）
        // timestamp:現在時刻（gettimeofday()）
        cache->state = ARP_CACHE_STATE_INCOMPLETE;
        cache->pa = pa;
        gettimeofday(&(cache->timestamp), NULL);

        mutex_unlock(&mutex);

        // ARP要求の送信関数を呼び出す
        arp_request(iface, pa);

        // 問い合わせ中なのでINCOMPLETEを返す
        return ARP_RESOLVE_INCOMPLETE;
    }

    // 見つかったらエントリがINCOMPLETEのままだったらパケロスしているかもしれないので念のため再送する
    // タイムスタンプは更新しない
    if (cache->state == ARP_CACHE_STATE_INCOMPLETE) {
        mutex_unlock(&mutex);
        arp_request(iface, pa);
        return ARP_RESOLVE_INCOMPLETE;
    }

    // 見つかったらハードウェアアドレスをコピー
    memcpy(ha, cache->ha, ETHER_ADDR_LEN);

    mutex_unlock(&mutex);

    debugf("resolved, pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return ARP_RESOLVE_FOUND;
}

// ARPのタイマーハンドラ
static void arp_timer_handler(void) {
    struct arp_cache *entry;
    struct timeval now, diff;

    mutex_lock(&mutex); // ARPキャッシュへのアクセスをmutexで保護
    gettimeofday(&now, NULL);
    for (entry = caches; entry < tailof(caches); entry++) {
        // 未使用のエントリと静的エントリは除外
        if (entry->state != ARP_CACHE_STATE_FREE && entry->state != ARP_CACHE_STATE_STATIC) {
            // エントリのタイムスタンプから現在までの経過時間を求める
            timersub(&now, &entry->timestamp, &diff);

            // タイムアウト時間（ARP_CACHE_TIMEOUT）が経過していたらエントリを削除する
            if (diff.tv_sec > ARP_CACHE_TIMEOUT)
                arp_cache_delete(entry);
        }
    }
    mutex_unlock(&mutex);
}

int arp_init(void) {
    struct timeval interval = {1, 0}; /* 1s */

    // ARPの入力関数(arp_input)をIPに登録
    // プロトコル番号はnet.hに定義してある定数を使う
    if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }

    // ARPのタイマーハンドラを登録
    if (net_timer_register(interval, arp_timer_handler) == -1) {
        errorf("net_timer_register() failure");
        return -1;
    }
    return 0;
}
