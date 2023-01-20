#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"
#include "util.h"
#include "net.h"

#define DUMMY_MTU UINT16_MAX /* maximum size of IP datagram */

#define DUMMY_IRQ INTR_IRQ_BASE

static int dummy_transmit(
    struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst) {
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    // drop data データを破棄

    // テスト用に割り込みを発生させる
    intr_raise_irq(DUMMY_IRQ);
    return 0;
}

static int dummy_isr(unsigned int irq, void *id) {
    debugf("irq=%u, dev=%s", irq, ((struct net_device *)id)->name);
    return 0;
}

// デバイスドライバが実装している関数へのポインタを設定する
static struct net_device_ops dummy_ops = {
    .transmit = dummy_transmit, // 送信関数(transmit)のみ設定
};

struct net_device *dummy_init(void) {
    struct net_device *dev;

    // デバイスを設定
    dev = net_device_alloc();
    if (!dev) {
        errorf("net_device_alloc() failure");
        return NULL;
    }

    dev->type = NET_DEVICE_TYPE_DUMMY; // 種別はnet.hに定義してある
    dev->mtu = DUMMY_MTU;
    dev->hlen = 0; // ヘッダは存在しない
    dev->alen = 0; // アドレスは存在しない
    dev->ops = &dummy_ops; // デバイスドライバが実装している関数へのポインタを設定する
    
    // デバイスを登録する
    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failure");
        return NULL;
    }
    
    // 割り込みハンドラとして dummy_isr を登録する
    intr_request_irq(DUMMY_IRQ, dummy_isr, INTR_IRQ_SHARED, dev->name, dev);
    debugf("initialized, dev=%s", dev->name);
    return dev;
}
