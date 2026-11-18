/*
 * IntentsHelperProbe v1.0.0
 *
 * 目标：回答「intents_helper 的 CPU 尖峰到底在执行什么代码」。
 *
 * 设计（与 CacheDeleteQuiet / SearchPartyQuiet 同路：纯 constructor，
 * 不链接 substrate / ellekit / Foundation / UIKit，避免 launchd XPC
 * daemon 因重框架 dlopen 失败而静默不注入）：
 *
 *   1. constructor 起一个 detached pthread 作为采样线程。
 *   2. 每 ~100ms 用 mach task_threads + thread_info(THREAD_BASIC_INFO)
 *      读本进程所有线程的 user_time+system_time，累加得进程总 CPU 时间。
 *      注意：设备 shell 的 `ps -o time` 对所有进程恒为 0:00.00（实测），
 *      但内核 thread_info 是准的 —— 所以必须在进程内采样，不能靠 ps。
 *   3. 进程 CPU 增量 / wall 增量 > 阈值(默认 50% 单核) 且过了冷却期 ⇒ 判尖峰。
 *   4. 尖峰时对每个线程 thread_get_state(ARM_THREAD_STATE64) 取 PC/LR/FP，
 *      沿 FP 链回溯最多 16 层，dladdr 就地符号化(image 名 + offset + 可选符号)，
 *      write() 追加到日志。不做任何 hook，不改变目标行为。
 *
 * arm64e PAC：thread_get_state 返回的 PC/LR/FP 由内核 strip 过；FP 链里
 * 的 LR 是签名值，读取后统一 ptrauth_strip 再 dladdr，避免符号化落到垃圾地址。
 *
 * 日志：ctor 里多候选 open 取首个成功 fd（与 CacheDeleteQuiet/SearchPartyQuiet
 * 完全同一已验证范式）：/var/mobile/Library/Logs/ → /var/tmp/ → /private/var/tmp/
 * → /var/mobile/Documents/ → $TMPDIR，文件名 ih_probe_<pid>.log。BOOT 行会打印
 * 实际锁定路径。root SSH 读取时统一加 /rootfs/private 头。
 *
 * flag：/rootfs/private/var/tmp/ih_probe.disabled 存在则 constructor 直接返回，
 *       用于老板不需要时一键停采（无需卸载 deb）。
 */

#include <mach/mach.h>
#include <mach/thread_info.h>
#include <mach/thread_act.h>
#include <mach/arm/thread_status.h>
#include <pthread.h>
#include <dlfcn.h>
#include <ptrauth.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* 每实例独立日志：intents_helper 是多实例 XPC，共写一个文件会交错不可读。
 * 落盘范式照抄已验证的 CacheDeleteQuiet/SearchPartyQuiet：ctor 里多候选
 * open 一次、持有全局 fd，首个成功者锁定路径。单硬编码路径必然静默失败
 * （沙盒守护进程视图与 SSH 不同，/var/tmp 曾踩坑）。 */
#define IHP_DISABLE_FLAG "/rootfs/private/var/tmp/ih_probe.disabled"

/* 候选目录：按「mobile 身份注入进程可写」排序，已实测 mobile 对 /var/tmp、
 * /private/var/tmp、Documents 可写，对 /var/mobile/Library/Logs 不可写(属
 * _analyticsusers)。注入进程写无头 /var/...，SSH 用 /rootfs/private 头读到
 * 同一处 —— 由 SearchPartyQuiet.log(注入 searchpartyd)实测印证。
 * /var/tmp 置首：CacheDeleteQuiet 实测的就是这个落点。 */
static const char *IHP_LOG_DIRS[] = {
    "/var/tmp",
    "/private/var/tmp",
    "/var/mobile/Documents",
    "/var/mobile/Library/Logs",
};

static int      g_logfd = -1;
static char     g_logpath[256] = "(none)";
static int      g_open_errno = 0;

#define IHP_INTERVAL_US   100000   /* 100ms 采样间隔 */
#define IHP_SPIKE_PCT     50       /* 进程总 CPU > 50% 单核判尖峰 */
#define IHP_COOLDOWN_S    2        /* 同进程两次 dump 最小间隔(秒) */
#define IHP_MAX_DUMPS     500      /* 日志上限，防止长期挂无限增长 */
#define IHP_FP_DEPTH      16
#define IHP_FRAME_BYTES   16       /* arm64 frame record = {fp, lr} = 16B */

/* ctor 调用：多候选取首个成功 fd（与 CacheDeleteQuiet open_log 同法） */
static void ihp_open_log(void) {
    char name[96];
    snprintf(name, sizeof(name), "ih_probe_%d.log", (int)getpid());
    for (size_t i = 0; i < sizeof(IHP_LOG_DIRS)/sizeof(IHP_LOG_DIRS[0]); i++) {
        char p[256];
        int n = snprintf(p, sizeof(p), "%s/%s", IHP_LOG_DIRS[i], name);
        if (n <= 0 || n >= (int)sizeof(p)) continue;
        int fd = open(p, O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (fd >= 0) {
            g_logfd = fd;
            strncpy(g_logpath, p, sizeof(g_logpath)-1);
            return;
        }
        g_open_errno = errno;
    }
    /* 最后兜底：TMPDIR（沙盒容器私有临时目录），v1.0.1/1.0.2 陷阱是把它当首选 */
    const char *tmp = getenv("TMPDIR");
    if (tmp && *tmp) {
        char p[256];
        int n = snprintf(p, sizeof(p), "%s/%s", tmp, name);
        if (n > 0 && n < (int)sizeof(p)) {
            int fd = open(p, O_WRONLY | O_APPEND | O_CREAT, 0644);
            if (fd >= 0) {
                g_logfd = fd;
                strncpy(g_logpath, p, sizeof(g_logpath)-1);
            }
        }
    }
}

/* 向 ctor 已持有的 fd 追加（无反复 open，开销低） */
static void ihp_append(const char *buf, size_t len) {
    if (g_logfd < 0) return;
    (void)!write(g_logfd, buf, len);
}
static void ihp_line(const char *fmt, ...) {
    char b[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    if (n > 0) ihp_append(b, (size_t)n < sizeof(b) ? (size_t)n : sizeof(b) - 1);
}

/* ---------- 时间工具 ---------- */
static uint64_t now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

/* ---------- 取本进程所有线程的 CPU 时间(us) ---------- */
static uint64_t proc_cpu_us(thread_array_t *out_threads, mach_msg_type_number_t *out_count) {
    thread_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    kern_return_t kr = task_threads(mach_task_self(), &threads, &count);
    if (kr != KERN_SUCCESS) return 0;
    uint64_t total = 0;
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        thread_basic_info_data_t bi;
        mach_msg_type_number_t bic = THREAD_BASIC_INFO_COUNT;
        if (thread_info(threads[i], THREAD_BASIC_INFO,
                        (thread_info_t)&bi, &bic) == KERN_SUCCESS) {
            total += (uint64_t)bi.user_time.seconds * 1000000ULL + bi.user_time.microseconds;
            total += (uint64_t)bi.system_time.seconds * 1000000ULL + bi.system_time.microseconds;
        }
    }
    *out_threads = threads;
    *out_count = count;
    return total;
}

/* ---------- 符号化单个 PC，写一行 ---------- */
static void ihp_frame(int idx, uint64_t pc) {
    if (pc == 0) return;
    Dl_info info;
    memset(&info, 0, sizeof(info));
    int ok = dladdr((void *)(uintptr_t)pc, &info);
    const char *img = "?";
    if (ok && info.dli_fname) {
        const char *slash = strrchr(info.dli_fname, '/');
        img = slash ? slash + 1 : info.dli_fname;
    }
    uintptr_t off = 0;
    if (ok && info.dli_fbase) {
        off = (uintptr_t)pc - (uintptr_t)info.dli_fbase;
    }
    if (ok && info.dli_sname && info.dli_saddr &&
        (uintptr_t)pc >= (uintptr_t)info.dli_saddr) {
        ihp_line("  [%02d] %s +0x%llx  (%s+0x%llx)",
                 idx, img, (unsigned long long)off,
                 info.dli_sname,
                 (unsigned long long)((uintptr_t)pc - (uintptr_t)info.dli_saddr));
    } else {
        ihp_line("  [%02d] %s +0x%llx", idx, img, (unsigned long long)off);
    }
}

/* ---------- dump 一个线程的栈 ---------- */
static void ihp_dump_thread(mach_port_t th, int tidx) {
    arm_thread_state64_t st;
    mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
    if (thread_get_state(th, ARM_THREAD_STATE64,
                         (thread_state_t)&st, &sc) != KERN_SUCCESS) return;

    uint64_t pc = (uint64_t)arm_thread_state64_get_pc(st);
    uint64_t lr = (uint64_t)arm_thread_state64_get_lr(st);
    uint64_t fp = (uint64_t)arm_thread_state64_get_fp(st);

    ihp_line(" T%d:", tidx);
    ihp_frame(0, pc);
    if (lr && lr != pc) ihp_frame(1, (uint64_t)ptrauth_strip((void *)(uintptr_t)lr, ptrauth_key_asia));

    int depth = 2;
    uint64_t cur = (uint64_t)ptrauth_strip((void *)(uintptr_t)fp, ptrauth_key_asia);
    for (int i = 0; i < IHP_FP_DEPTH && cur && depth < IHP_FP_DEPTH; i++) {
        uint64_t words[2] = {0, 0};
        vm_size_t got = 0;
        kern_return_t kr = vm_read_overwrite(mach_task_self(),
                              (vm_address_t)cur, IHP_FRAME_BYTES,
                              (vm_address_t)words, &got);
        if (kr != KERN_SUCCESS || got != IHP_FRAME_BYTES) break;
        uint64_t next = (uint64_t)ptrauth_strip((void *)(uintptr_t)words[0], ptrauth_key_asia);
        uint64_t ret  = (uint64_t)ptrauth_strip((void *)(uintptr_t)words[1], ptrauth_key_asia);
        if (ret) ihp_frame(depth++, ret);
        if (next <= cur) break;           /* 链条回退/停滞，停 */
        cur = next;
    }
}

/* ---------- 采样线程主循环 ---------- */
static void *ihp_sampler(void *arg) {
    (void)arg;
    uint64_t prev_cpu = 0, prev_wall = now_us();
    uint64_t last_dump = 0;
    int dumps = 0;

    ihp_line("BOOT pid=%d interval=%dus spike>=%d%% cooldown=%ds depth=%d log=%s errno=%d",
             (int)getpid(), IHP_INTERVAL_US, IHP_SPIKE_PCT, IHP_COOLDOWN_S,
             IHP_FP_DEPTH, g_logpath, g_open_errno);

    while (dumps < IHP_MAX_DUMPS) {
        usleep(IHP_INTERVAL_US);
        uint64_t wall = now_us();

        thread_array_t threads = NULL;
        mach_msg_type_number_t count = 0;
        uint64_t cpu = proc_cpu_us(&threads, &count);
        uint64_t dwall = wall - prev_wall;
        uint64_t dcpu = (cpu >= prev_cpu) ? (cpu - prev_cpu) : 0;
        int pct = dwall ? (int)((dcpu * 100ULL) / dwall) : 0;

        if (pct >= IHP_SPIKE_PCT && (wall - last_dump) >= (uint64_t)IHP_COOLDOWN_S * 1000000ULL) {
            last_dump = wall;
            dumps++;
            ihp_line("=== SPIKE #%d %llu.%03llu cpu=%d%% threads=%u ===",
                     dumps,
                     (unsigned long long)(wall / 1000000ULL),
                     (unsigned long long)((wall / 1000ULL) % 1000ULL),
                     pct, (unsigned)count);
            for (mach_msg_type_number_t i = 0; i < count; i++) {
                ihp_dump_thread(threads[i], (int)i);
            }
            ihp_line("=== END #%d ===", dumps);
        }

        if (threads) vm_deallocate(mach_task_self(), (vm_address_t)threads,
                                   (vm_size_t)(count * sizeof(thread_t)));
        prev_cpu = cpu;
        prev_wall = wall;
    }
    ihp_line("STOP max-dumps=%d reached", IHP_MAX_DUMPS);
    return NULL;
}

__attribute__((constructor)) static void ihp_init(void) {
    if (access(IHP_DISABLE_FLAG, F_OK) == 0) return;
    /* 多候选锁定日志路径（ctor 里 open 一次，取首个成功 fd） */
    ihp_open_log();
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, ihp_sampler, NULL) != 0) {
        ihp_line("ERROR pthread_create failed errno=%d", errno);
    }
    pthread_attr_destroy(&attr);
}
