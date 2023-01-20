#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "driver/ether_tap.h"

#include "driver/loopback.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s) {
    (void)s;
    terminate = 1;
}

static int setup(void) {
    struct net_device *dev;
    struct ip_iface *iface;
    
    signal(SIGILL, on_signal); // シグナルハンドラの設定（Ctrl+Cが押された際にお行儀よく終了するように）

    // プロトコルスタックの初期化
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }

    // loopbackデバイスの初期化（デバイスドライバがプロトコルスタックへの登録まで済ませる）
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() faulure");
        return -1;
    }

    // IPアドレスとサブネットマスクを指定してIPインタフェースを生成
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }

    // IPインタフェースの登録
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }

    // ループバックデバイスはそのままに、新しくEthernetデバイスに関するコードを追記する

    // Ethernetデバイスの生成
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        errorf("ether_tap_init() failure");
        return -1;
    }

    // IPインタフェースを生成して紐づける
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }

    // プロトコルスタックの起動
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}

static void cleanup(void) {
    // プロトコルスタックの停止
    net_shutdown();
}

int main(int argc, char *argv[]) {
    signal(SIGINT, on_signal);

    // プロトコルスタックの初期化～デバイス登録～起動までのセットアップ
    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }

    // Ctrl+Cが押されるとシグナルハンドラ on_signal() の中で terminate に1が設定される
    while (!terminate) {
        sleep(1);
    }

    // net_shutdown()はcleanup()に移動
    cleanup();

    return 0;
}
