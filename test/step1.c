#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"

#include "driver/dummy.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s) {
    (void)s;
    terminate = 1;
}

int main(int argc, char *argv[]) {
    struct net_device *dev;

    signal(SIGILL, on_signal); // シグナルハンドラの設定（Ctrl+Cが押された際にお行儀よく終了するように）
    
    // プロトコルスタックの初期化
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }

    // ダミーデバイスの初期化（デバイスドライバがプロトコルスタックへの登録まで済ませる）
    debugf("initialized start");
    dev = dummy_init();
    if (!dev) {
        errorf("dummy_init() faulure");
        return -1;
    }

    // プロトコルスタックの起動
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }

    // Ctrl+Cが押されるとシグナルハンドラ on_signal() の中で terminate に1が設定される
    while (!terminate) {
        // 1秒おきにデバイスにパケットを書き込む
        // またパケットを自力で生成できないのでテストデータを用いる
        if (net_device_output(dev, 0x0000, test_data, sizeof(test_data), NULL) == -1) {
            errorf("net_device_output() failure");
            break;
        }
        sleep(1);
    }

    // プロトコルスタックの停止
    net_shutdown();
    return 0;
}
