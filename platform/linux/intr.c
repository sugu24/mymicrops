#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"
#include "util.h"
#include "net.h"

// 割り込み番号を表現する構造体
struct irq_entry {
    struct irq_entry *next;
    unsigned int irq;
    int (*handler) (unsigned int irq, void *dev);
    int flags;
    char name[16];
    void *dev; // 割り込みの発生元デバイス
};

static struct irq_entry *irqs;
static sigset_t sigmask; // シグナルマスク用のシグナル集合

static pthread_t tid; // 割り込み処理スレッドのスレッドID
static pthread_barrier_t barrier; // スレッド間の同期のためのバリア

// 割り込みハンドラを登録
int intr_request_irq(unsigned int irq, int (*handler) (unsigned int irq, void *dev), int flags, const char *name, void *dev) {
    struct irq_entry *entry;

    debugf("irq=%u, flags=%d, name=%s", irq, flags, name);
    for (entry = irqs; entry; entry = entry->next) {
        if (entry->irq == irq) {
            // IRQ番号が登録されており、共有可能でない場合エラー
            if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED) {
                errorf("conflicts with already registerd IRQs");
                return -1;
            }
        }
    }

    // IRQリストへ新しいエントリを追加

    // メモリ確保
    entry = memory_alloc(sizeof(*entry));
    if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
    }
    // 設定していく
    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    strncpy(entry->name, name, sizeof(entry->name)-1);
    entry->dev = dev;
    entry->next = irqs;
    irqs = entry;

    // シグナル集合へ新しいシグナルを追加
    sigaddset(&sigmask, irq);
    debugf("regissterd: irq=%u, name=%s", irq, name);
    return 0;
}

int intr_raise_irq(unsigned int irq) {
    // 割り込み処理スレッドへシグナルを送信
    return pthread_kill(tid, (int)irq);
}

// タイマーのための周期処理
static int intr_timer_setup(struct itimerspec *interval) {
    timer_t id;

    // タイマーの作成
    if (timer_create(CLOCK_REALTIME, NULL, &id) == -1) {
        errorf("timer_create: %s", strerror(errno));
        return -1;
    }

    // インターバルの設定
    if (timer_settime(id, 0, interval, NULL) == -1) {
        errorf("timer_settime: %s", strerror(errno));
        return -1;
    }
    return 0;
}

// 割り込みスレッドのエントリポイント
static void *intr_thread(void *arg) {
    const struct timespec ts = {0, 1000000}; /* 1ms */
    struct itimerspec interval = {ts, ts};
    int terminate = 0, sig, err;
    struct irq_entry *entry;

    debugf("start...");
    pthread_barrier_wait(&barrier); // メインスレッドと同期を取るための処理
    
    // 周期処理用タイマーのセットアップ
    if (intr_timer_setup(&interval) == -1) {
        errorf("intr_timer_setup() failure");
        return NULL;
    }

    while (!terminate) {
        // 割り込みに見立てたシグナルが発生するまで待機
        err = sigwait(&sigmask, &sig);
        if (err) {
            errorf("sigwait() %s", strerror(err));
            break;
        }

        // 発生したシグナルに応じた処理を実行
        switch (sig) {
            case SIGHUP: // 割り込みスレッドへ終了を通知するためのシグナル
                terminate = 1;
                break;
            case SIGUSR2:
                net_event_handler(); // イベント用のシグナルを補足したらnet_event_handler()を呼び出す
                break;
            case SIGALRM:
                // 周期処理用タイマーが発火した際の処理
                net_timer_handler();
                break;
            case SIGUSR1:
                // ソフトウェア割り込み用のシグナル（SIGUSR1）を捕捉した際の処理を通知
                // net_softirq_handler()を呼び出す
                net_softirq_handler();
                break;
            default:
                for (entry = irqs; entry; entry = entry->next) {
                    // IRQ番号が一致するエントリの割り込みハンドラを呼び出す
                    if (entry->irq == (unsigned int) sig) {
                        entry->handler(entry->irq, entry->dev);
                    }
                }
                break;
        }
    }
    debugf("terminated");
    return NULL;
}

int intr_run(void) {
    int err;

    // シグナルマスクの設定
    err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL); // sig_blockはシグナルマスクに追加
    if (err) { 
        errorf("pthread_sigmask() %s", strerror(err));
        return -1;
    }

    // 割り込み処理スレッドを起動
    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if (err) {
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }

    // スレッドが動き出すまで待つ
    // 他のスレッドが同じようにpthread_barrier_wait()を呼び出し、
    // バリアのカウントが指定の数になるまでスレッドを停止する
    pthread_barrier_wait(&barrier);
    return 0;
}

void intr_shutdown(void) {
    // 割り込み処理スレッドが起動済みかどうか確認
    if (pthread_equal(tid, pthread_self()) != 0) {
        /* Thread not create */
        return;
    }

    // 割り込み処理スレッドにシグナル(SIGHUP)を送信
    pthread_kill(tid, SIGHUP);

    // 割り込み処理スレッドが完全に終了するまで待つ
    pthread_join(tid, NULL);
}

int intr_init(void) {
    // スレッドIDの初期値にメインスレッドのIDを設定する
    tid = pthread_self();

    // pthread_barrierの初期化（カウントを2に設定）
    pthread_barrier_init(&barrier, NULL, 2);

    // シグナル集合を初期化（空にする）
    sigemptyset(&sigmask);

    // ソフトウェア割り込みとして使用するSIGUSR1を捕捉するためにマスク用シグナル集合へ追加
    sigaddset(&sigmask, SIGUSR1);

    // シグナル集合にSIGHUPを追加（割り込みスレッド終了通知用）
    sigaddset(&sigmask, SIGHUP);

    // イベント用のシグナルをシグナルマスクの集合へ追加
    sigaddset(&sigmask, SIGUSR2);

    // 周期処理タイマー発火時に昇進されるシグナルを追加
    sigaddset(&sigmask, SIGALRM);
    return 0;
}

