#define _GNU_SOURCE /* for F_SETSIG */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"

#include "driver/ether_tap.h"

#define CLONE_DEVICE "/dev/net/tun"

#define ETHER_TAP_IRQ (INTR_IRQ_BASE+2)

struct ether_tap {
    char name[IFNAMSIZ]; // TAPデバイスの名前
    int fd;              // ファイルディスクリプタ
    unsigned int irq;    // IRQ番号
};

#define PRIV(x) ((struct ether_tap *)x->priv)

// Ethernetデバイス（TAP）HWアドレスの取得
static int ether_tap_addr(struct net_device *dev) {
    int soc;
    struct ifreq ifr = {}; // ioctl()で使うリクエスト/レスポンス兼用の構造体

    // 何でもいいのでsocketをオープンする
    // 通信するわけでもないのにソケットをオープンしている理由 
    // … ioctl() の SIOCGIFHWADDR 要求がソケットとして開かれたディスクリプタでのみ有効なため
    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1) {
        errorf("socket: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }

    // HWアドレスを取得したいデバイスの名前を設定する
    strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name)-1);
    
    // ハードウェアアドレスの取得を要求する
    if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1) {
        errorf("ioctl [SIOCGIFHWADDR]: %s, dev=%s", strerror(errno), dev->name);
        close(soc);
        return -1;
    }

    // 取得したアドレスをデバイス構造体へコピー
    memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    
    // 使い終わったsocketをクローズ
    close(soc);
    return 0;
}

// Ethernetデバイス（TAP）オープン/クローズ
static int ether_tap_open(struct net_device *dev) {
    struct ether_tap *tap;
    struct ifreq ifr = {}; // ioctl()で使うリクエスト/レスポンス兼用の構造体 

    tap = PRIV(dev);

    // TUN/TAPの制御用デバイスをオープン
    tap->fd = open(CLONE_DEVICE, O_RDWR);
    if (tap->fd == -1) {
        errorf("open: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }

    // TAPデバイスの名前を設定
    strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name)-1);

    // フラグ設定（IFF_TAP:TAPモード, IFF_NO_PI:パケット情報ヘッダをつけない）
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    // TAPデバイスの登録を要求
    // ioctl()でTAPデバイスの生成に成功したらdev->fdをread()/write()することでEthernetフレームの送受信ができるようになる
    if (ioctl(tap->fd, TUNSETIFF, &ifr) == -1) {
        errorf("ioctl[TUNSeTIFF]: %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }

    // シグナル駆動I/Oのための設定

    // Set Asynchronous I/O signal delivery destination
    // シグナル配送先設定
    if (fcntl(tap->fd, F_SETOWN, getpid()) == -1) {
        errorf("fcntl(F_SETOWN): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }
    // Enable Asynchronous I/O
    // シグナル駆動I/Oを有効にする
    if (fcntl(tap->fd, F_SETFL, O_ASYNC) == -1) {
        errorf("fcntl(F_SETFL): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }
    // Use other signal instead of SIGIO
    // 送信するシグナルを指定
    if (fcntl(tap->fd, F_SETSIG, tap->irq) == -1) {
        errorf("fcntl(F_SETSIG): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }

    //HWアドレスが明示的に設定されていなかったら
    if (memcmp(dev->addr, ETHER_ADDR_ANY, ETHER_ADDR_LEN) == 0) {
        // OS側から見えているTAPデバイスのHWアドレスを取得して使用する
        if (ether_tap_addr(dev) == -1) {
            errorf("ether_tap_addr() failure, dev=%s", dev->name);
            close(tap->fd);
            return -1;
        }
    }
    return 0;
}

static int ether_tap_close(struct net_device *dev) {
    // ディスクリプタをクローズ
    close(PRIV(dev)->fd);
    return 0;
}

// Ethernetデバイス（TAP）送信関数
static ssize_t ether_tap_write(struct net_device *dev, const uint8_t *frame, size_t flen) {
    // write()で書き出すだけ
    return write(PRIV(dev)->fd, frame, flen);
}

/*
    net_device_output()から送信する過程

    net_device_output() ->
    ether_tap_transmit() ->
    ether_transmit_helper() ->
    ether_tap_write() ->
    write()
*/
int ether_tap_transmit(struct net_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void *dst) {
    // ether_transmit_helper()を呼び出す
    // コールバック関数としてether_tap_write()のアドレスを渡す
    return ether_transmit_helper(dev, type, buf, len, dst, ether_tap_write);
}

static ssize_t ether_tap_read(struct net_device *dev, uint8_t *buf, size_t size) {
    ssize_t len;

    // read()で呼び出すだけ
    len = read(PRIV(dev)->fd, buf, size);
    if (len <= 0) {
        if (len == -1 && errno != EINTR) {
            errorf("read: %s, dev=%s", strerror(errno), dev->name);
        }
        return -1;
    }
    return len;
}

// Ethernetデバイス（TAP）の割り込みハンドラ
/*
    割り込みハンドラの流れ
    
    ether_tap_isr() ->
    ether_input_helper() ->
    ether_tap_read() ->
*/
static int ether_tap_isr(unsigned int irq, void *id) {
    struct net_device *dev;
    struct pollfd pfd;
    int ret;

    dev = (struct net_device *)id;
    pfd.fd = PRIV(dev)->fd;
    pfd.events = POLLIN;
    while (1) {
        // タイムアウト時間を0に設定したpoll()で読み込み可能なデータの存在を確認
        ret = poll(&pfd, 1, 0);
        if (ret == -1) {
            if (errno == EINTR) {
                // errnoがEINTRの場合は再試行（シグナルに割り込まれたという回復可能なエラー）
                continue;
            }
            errorf("poll: %s, dev=%s", strerror(errno), dev->name);
            return -1;
        }
        if (ret == 0) {
            // 戻り値が0だったらタイムアウト（読み込み可能なデータなし）
            break;
        }
        //読み込み可能だったらether_input_helper()を呼び出す
        // コールバック関数としてether_tap_read()のアドレスを渡す
        ether_input_helper(dev, ether_tap_read);
    }
    return 0;
}

static struct net_device_ops ether_tap_ops = {
    .open = ether_tap_open,
    .close = ether_tap_close,
    .transmit = ether_tap_transmit,
};

// Ethernetデバイス（TAP）の生成
struct net_device *ether_tap_init(const char *name, const char *addr) {
    struct net_device *dev;
    struct ether_tap *tap;

    // デバイスを生成
    dev = net_device_alloc();
    if (!dev) {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    // Ethernetデバイスの共通パラメータを設定
    ether_setup_helper(dev);

    // 引数でハードウェアアドレスの文字列が渡されたら
    // それをバイト列に変換して設定する
    if (addr) {
        if (ether_addr_pton(addr, dev->addr) == -1) {
            errorf("invalid address, addr=%s", addr);
            return NULL;
        }
    }

    // ドライバの関数群を設定
    dev->ops = &ether_tap_ops;

    // ドライバ内部で使用するプライベートなデータを生成＆保持
    tap = memory_alloc(sizeof(*tap));
    if (!tap) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    strncpy(tap->name, name, sizeof(tap->name)-1);
    tap->fd = -1; // 初期値として無効な値を設定しておく
    tap->irq = ETHER_TAP_IRQ;
    dev->priv = tap;

    // デバイスをプロトコルスタックに登録
    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failure");
        memory_free(tap);
        return NULL;
    }

    // 割り込みハンドラの登録
    intr_request_irq(tap->irq, ether_tap_isr, INTR_IRQ_SHARED, dev->name, dev);
    
    infof("ethernet device initialized, dev=%s", dev->name);
    return dev;
}