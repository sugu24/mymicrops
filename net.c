#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"
#include "arp.h"
#include "udp.h"
#include "tcp.h"

struct net_protocol {
    struct net_protocol *next;
    uint16_t type; // プロトコルの種別（net.hにNET_PROTOCOL_TYPE_XXXとして定義）
    struct queue_head queue; /* input queue 受信キュー*/
    void (*handler) (const uint8_t *data, size_t len, struct net_device *dev); // プロトコルの入力関数へのポインタ
};

struct net_protocol_queue_entry {
    struct net_device *dev;
    size_t len;
    uint8_t data[];
};

// タイマーの構造体
struct net_timer {
    struct net_timer *next; // 次のタイマーへのポインタ
    struct timeval interval; // 発火のインターバル
    struct timeval last; // 最後の発火時間
    void (*handler)(void); // 発火時に呼び出す関数へのポインタ
};

struct net_event {
    struct net_event *next;
    void (*handler)(void *arg);
    void *arg;
};

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct net_device *devices;
static struct net_protocol *protocols;
static struct net_timer *timers;
static struct net_event *events;

struct net_device *net_device_alloc(void) {
    struct net_device *dev; // net_deviceの情報を指すポインタ

    dev = memory_alloc(sizeof(*dev));
    if (!dev) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    return dev;
}

/* NOTE: must not be call after net_run() */
// set name and index. add devices 
int net_device_register(struct net_device *dev) {
    static unsigned int index = 0;

    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);
    dev->next = devices;
    devices = dev;
    infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);
    return 0;
}

/* NOTE: must not be call after net_run() */
int net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev)) {
    struct net_protocol *proto;

    // 重複登録の確認
    for (proto = protocols; proto; proto = proto->next) {
        if (type == proto->type) {
            errorf("already registerd, type=0x%04x", type);
            return -1;
        }
    }

    // プロトコル構造体のメモリを確保
    proto = memory_alloc(sizeof(*proto));
    if (!proto) {
        errorf("memory_alloc() failure");
        return -1;
    }

    // プロトコル種別と入力関数を設定
    proto->type = type;
    proto->handler = handler;

    // プロトコルリストの先頭に追加
    proto->next = protocols;
    protocols = proto;

    infof("registered, type=0x%04x", type);
    return 0;
}

static int net_device_open(struct net_device *dev) {
    // デバイスの状態を確認
    // デバイスの状態を確認（既にUP状態の場合はエラーを返す）
    if (NET_DEVICE_IS_UP(dev)) {
        errorf("already opened, dev=%s", dev->name);
        return -1;
    }
    
    // デバイスドライバのオープン関数を呼び出す
    // オープン関数が設定されていない場合は呼び出しをスキップ
    // エラーが返されたらこの関数もエラーを返す
    if (dev->ops->open) {
        if (dev->ops->open(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }
    // UPフラグを立てる
    dev->flags |= NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

static int net_device_close(struct net_device *dev) {
    // デバイスの状態を確認（UP状態でない場合はエラーを返す）
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }

    // デバイスドライバのクローズ関数を呼び出す
    // クローズ関数が設定されていない場合は呼び出しをスキップ
    // エラーが返されてたらこの関数もエラーを返す
    if (dev->ops->close) {
        if (dev->ops->close(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }

    // UPフラグを落とす
    dev->flags &= ~NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

/* NOTE: must not be call after net_run() */
int net_device_add_iface(struct net_device *dev, struct net_iface *iface) {
    struct net_iface *entry;

    for (entry = dev->ifaces; entry; entry = entry->next) {
        if (entry->family == iface->family) {
            /* NOTE: For simplicity, only one iface can be added per family. */
            errorf("already exists, dev=%s, family%d", dev->name, entry->family);
            return -1;
        }
    }
    iface->dev = dev;

    // デバイスのインタフェースリストの先頭にifaceを挿入
    iface->next = dev->ifaces;
    dev->ifaces = iface;

    return 0;
}

struct net_iface *net_device_get_iface(struct net_device *dev, int family) {
    // デバイスに紐づくインタフェースを巡回
    // . familyが一致するインタフェースを返す
    // 合致するインタフェースを発見できなかったらNULLを返す
    struct net_iface *iface;

    for (iface = dev->ifaces; iface; iface = iface->next) {
        if (iface->family == family)
            return iface;
    }
    return NULL;
}

int net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst) {
    // デバイスの状態を確認（UP状態でなければ送信できないのでエラーを返す）
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened dev=%s", dev->name);
        return -1;
    }

    // データのサイズを確認（デバイスのMTUを超えるサイズのデータは送信できないのでエラーを返す）
    if (len > dev->mtu) {
        errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
        return -1;
    }

    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);

    // デバイスドライバの出力関数を呼び出す（エラーが返されたらこの関数もエラーを返す）
    if (dev->ops->transmit(dev, type, data, len, dst) == -1) {
        errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
        return -1;
    }
    return 0;
}

/* NOTE: must not be call after net_run() */
int net_timer_register(struct timeval interval, void (*handler)(void)) {
    struct net_timer *timer;

    // タイマーの構造体のメモリを確保
    timer = memory_alloc(sizeof(*timer));
    if (!timer) {
        errorf("memory_alloc() failure");
        return -1;
    }

    // タイマーに値を設定
    timer->interval = interval;
    gettimeofday(&(timer->last), NULL);
    timer->handler = handler;

    // タイマーリストの先頭に追加
    timer->next = timers;
    timers = timer;

    infof("registered: interval={%d, %d}", interval.tv_sec, interval.tv_usec);
    return 0;
}

// タイマーの確認と発火
int net_timer_handler(void) {
    struct net_timer *timer;
    struct timeval now, diff;

    for (timer = timers; timer; timer = timer->next) {
        gettimeofday(&now, NULL);
        timersub(&now, &timer->last, &diff); // 最初の発火からの経過時間を求める

        // 発火時刻を迎えているかどうかの確認
        if (timercmp(&timer->interval, &diff, <) != 0) {
            // 登録されている関数を呼び出す
            timer->handler();
            
            // 最後の発火時間を更新
            timer->last = now;
        }
    }
    return 0;
}

// デバイスドライバから呼び出される想定
// プロトコルスタックに受信したパケットを渡す関数    
int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev) {
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    debugf("start...");

    for (proto = protocols; proto; proto = proto->next) {
        // プロトコルのtypeが一致
        if (proto->type == type) {
            // entryのメモリ確保
            entry = memory_alloc(sizeof(*entry) + len);
            if (!entry) {
                errorf("memory_alloc() failure");
                return -1;
            }
            
            // 新しいエントリへメタデータの設定と受信データのコピー
            entry->len = len;
            entry->dev = dev;
            memcpy(entry->data, data, len);

            // エントリをキューへ格納
            queue_push(&proto->queue, entry);
            
            debugf("queue pushed (num:%u), dev=%s, type=0x04x, len=%zu", proto->queue.num, dev->name, type, len);
            debugdump(data, len);

            // プロトコルの受信キューへエントリを追加した後、
            // ソフトウェア割り込みを発生させる
            intr_raise_irq(INTR_IRQ_SOFTIRQ);
            return 0;
        }
    }
    /* unsupported protocol */
    return 0;
}

// ソフトウェア割り込みが発生した際に呼び出してもらう関数
int net_softirq_handler(void) {
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    // プロトコルリストを巡回（全てのプロトコルを確認）
    for (proto = protocols; proto; proto = proto->next) {
        while (1) {
            // 受信キューからエントリを取り出す（エントリが存在する間処理を繰り返す）
            entry = queue_pop(&proto->queue);
            if (!entry) break;
            debugdump(entry->data, entry->len);

            // プロトコルの入力関数を呼び出す
            proto->handler(entry->data, entry->len, entry->dev);
            memory_free(entry);
        }
    }
    return 0;
}

/* NOTE: must not be call after net_run() */
int net_event_subscribe(void (*handler)(void *arg), void *arg) {
    struct net_event *event;

    event = memory_alloc(sizeof(*event));
    if (!event) {
        errorf("memory_alloc() failure");
        return -1;
    }
    event->handler = handler;
    event->arg = arg;
    event->next = events;
    events = event;
    return 0;
}

int net_event_handler(void) {
    struct net_event *event;

    // イベントを購読している全てのハンドラを呼び出す
    for (event = events; event; event = event->next)
        event->handler(event->arg);
    return 0;
}

void net_raise_event(void) {
    // イベント用の割り込みを発せさせる
    intr_raise_irq(INTR_IRQ_EVENT);
}

int net_run(void) {
    struct net_device *dev;

    // 割り込み機構を起動
    if (intr_run() == -1) {
        errorf("intr_run() failure");
        return -1;
    }

    debugf("open all devices ... ");

    // 登録済みの全デバイスをオープン
    for (dev = devices; dev; dev = dev->next) {
        net_device_open(dev);
    }
    
    debugf("running ...");
    return 0;
}

void net_shutdown(void) {
    struct net_device *dev;

    debugf("close all devies ...");

    // 登録済みの全デバイスをクローズ
    for (dev = devices; dev; dev = dev->next)
        net_device_close(dev);
    
    // 割り込み機構の終了
    intr_shutdown();
    debugf("shutting down");
}

#include "icmp.h"
int net_init(void) {
    // 割り込み機構の初期化
    if (intr_init() == -1) {
        errorf("intr_init() failure");
        return -1;
    }

    // ARPの初期化関数を呼び出す（データリンク層）
    if (arp_init() == -1) {
        errorf("arp_init() failure");
        return -1;
    }

    // プロトコルスタック初期化時にIPの初期化関数を呼び出す
    // プロトコルスタックにIPの入力関数を呼び出す
    if (ip_init() == -1) {
        errorf("ip_init() failure");
        return -1;
    }

    // ICMPの初期化関数を呼び出す（プロトコルスタックの初期化時にICMPが登録されるようにする）
    if (icmp_init() == -1) {
        errorf("icmp_init() failure");
        return -1;
    }

    if (udp_init() == -1) {
        errorf("udp_init() failure");
        return -1;
    }

    if (tcp_init() == -1) {
        errorf("tcp_init() failure");
        return -1;
    }

    infof("initialized");
    return 0;
}
