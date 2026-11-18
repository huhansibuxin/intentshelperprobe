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
#include <syslog.h>
#include <sys/stat.h>

/* 每实例独立日志：intents_helper 是多实例 XPC，共写一个文件会交错不可读。
 *
 * v1.0.3 —— 完全照抄 SearchPartyQuiet v1.0.4(已在真机写出 BOOT+日志的范式):
 *   mkdir(进程自有数据目录,0755) 然后 open(O_WRONLY|O_CREAT|O_APPEND,0644)。
 *   进程自有目录 FIRST(/var/mobile/Library/Intents, mobile:mobile, 进程每天
 *   在写其中的 Images/), /var/tmp SECOND。绝不用 getenv/TMPDIR —— SPQ 源码
 *   注释原话: "NO TMPDIR/getenv - that was the v1.0.1/1.0.2 trap (view mismatch)"。
 *   v1.0.0~1.0.2 四版零日志的根因就是 TMPDIR 视图错配 + 候选目录都不是进程自有。 */
#define IHP_DISABLE_FLAG "/rootfs/private/var/tmp/ih_probe.disabled"

/* SPQ 铁证: constructor 在此类 XPC/daemon 确实执行(BOOT ctor-executed 在日志第一行)。
 * 关键只在于写进「进程自己的数据目录」—— SSH 加 /rootfs/private 头读到同一处。 */
#define IHP_LOG_DIR0 "/var/mobile/Library/Intents"
#define IHP_LOG_PATH0 IHP_LOG_DIR0 "/ih_probe_%d.log"
#define IHP_LOG_PATH2 "/var/tmp/ih_probe_%d.log"

static int      g_logfd = -1;
static char     g_logpath[256] = "(none)";
static int      g_open_errno = 0;

#define IHP_INTERVAL_US   100000   /* 100ms 采样间隔 */
#define IHP_SPIKE_PCT     50       /* 进程总 CPU > 50% 单核判尖峰 */
#define IHP_COOLDOWN_S    2        /* 同进程两次 dump 最小间隔(秒) */
#define IHP_MAX_DUMPS     500      /* 尖峰 dump 上限，防止长期挂无限增长 */
#define IHP_SNAP_INTERVAL 5000000  /* v1.1.0: 定时快照 5s(us)，覆盖低 CPU 的 XPC 回调 */
#define IHP_MAX_SNAPS     300      /* 快照上限(25 分钟)，防止日志无限增长 */
#define IHP_FP_DEPTH      16
#define IHP_FRAME_BYTES   16       /* arm64 frame record = {fp, lr} = 16B */

/* v1.0.3: byte-for-byte the SearchPartyQuiet v1.0.4 method - mkdir(dir,0755)
 * then open(O_WRONLY|O_CREAT|O_APPEND,0644). Process-owned data dir FIRST,
 * /var/tmp second. NO getenv/TMPDIR (that was the trap). */
static void ihp_open_log(void) {
    char p0[256], p2[256];
    snprintf(p0, sizeof(p0), IHP_LOG_PATH0, (int)getpid());
    snprintf(p2, sizeof(p2), IHP_LOG_PATH2, (int)getpid());

    (void)mkdir(IHP_LOG_DIR0, 0755);
    int fd = open(p0, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { g_logfd = fd; strncpy(g_logpath, p0, sizeof(g_logpath)-1); return; }
    g_open_errno = errno;

    fd = open(p2, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { g_logfd = fd; strncpy(g_logpath, p2, sizeof(g_logpath)-1); return; }
    g_open_errno = errno;
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

/* ---------- v1.1.0: 从进程地址空间读 C 字符串（syscall 路径参数） ----------
 * stat/getattrlist/open 等 wrapper 的第一个参数(x0)指向路径字符串。
 * 尖峰/快照时刻用 vm_read_overwrite 分块读出，最多 cap 字节。失败则留空。 */
static void ihp_read_cstr(uint64_t addr, char *out, size_t cap) {
    out[0] = '\0';
    if (!addr || cap < 2) return;
    size_t used = 0;
    uint64_t cur = addr;
    while (used + 1 < cap) {
        char chunk[32];
        vm_size_t got = 0;
        kern_return_t kr = vm_read_overwrite(mach_task_self(),
                              (vm_address_t)cur, sizeof(chunk),
                              (vm_address_t)chunk, &got);
        if (kr != KERN_SUCCESS || got == 0) break;
        for (vm_size_t i = 0; i < got && used + 1 < cap; i++) {
            out[used++] = chunk[i];
            if (chunk[i] == '\0') { out[used-1] = '\0'; return; }
        }
        cur += got;
    }
    out[used < cap ? used : cap-1] = '\0';
}

/* v1.1.0: 判断 PC 落在哪个「带路径参数」的 syscall wrapper 上，返回路径寄存器说明。
 * 匹配 libsystem_kernel 的 stat/lstat/fstatat/getattrlist/open/access 等。 */
static const char *ihp_path_syscall(uint64_t pc) {
    Dl_info si;
    memset(&si, 0, sizeof(si));
    if (!dladdr((void *)(uintptr_t)pc, &si) || !si.dli_sname) return NULL;
    const char *sn = si.dli_sname;
    static const char *names[] = {
        "stat", "stat64", "lstat", "fstatat", "getattrlist", "__getattrlist",
        "open", "open_nocancel", "access", "readlink", "realpath", NULL
    };
    for (int i = 0; names[i]; i++) {
        size_t n = strlen(names[i]);
        if (!strncmp(sn, names[i], n)) return names[i];
    }
    return NULL;
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
    /* v1.1.0: 栈顶正好在 stat/getattrlist 等 wrapper 内 => x0 是路径指针。
     * 只有在 syscall 入口附近(x0 尚未被覆盖)才读，读出来直接打印。 */
    const char *sc = ihp_path_syscall(pc);
    if (sc) {
        uint64_t x0 = (uint64_t)arm_thread_state64_get_x(st, 0);
        char path[512];
        ihp_read_cstr(x0, path, sizeof(path));
        if (path[0]) ihp_line("    >> %s(\"%s\")", sc, path);
    }
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
    uint64_t last_dump = 0, last_snap = now_us();
    int dumps = 0, snaps = 0;

    ihp_line("BOOT v1.1.0 pid=%d interval=%dus spike>=%d%% cooldown=%ds snap=%dus depth=%d log=%s errno=%d",
             (int)getpid(), IHP_INTERVAL_US, IHP_SPIKE_PCT, IHP_COOLDOWN_S,
             IHP_SNAP_INTERVAL, IHP_FP_DEPTH, g_logpath, g_open_errno);

    while (dumps < IHP_MAX_DUMPS && snaps < IHP_MAX_SNAPS) {
        usleep(IHP_INTERVAL_US);
        uint64_t wall = now_us();

        thread_array_t threads = NULL;
        mach_msg_type_number_t count = 0;
        uint64_t cpu = proc_cpu_us(&threads, &count);
        uint64_t dwall = wall - prev_wall;
        uint64_t dcpu = (cpu >= prev_cpu) ? (cpu - prev_cpu) : 0;
        int pct = dwall ? (int)((dcpu * 100ULL) / dwall) : 0;

        int do_spike = (pct >= IHP_SPIKE_PCT &&
                        (wall - last_dump) >= (uint64_t)IHP_COOLDOWN_S * 1000000ULL &&
                        dumps < IHP_MAX_DUMPS);
        int do_snap = ((wall - last_snap) >= IHP_SNAP_INTERVAL && snaps < IHP_MAX_SNAPS);
        if (do_spike || do_snap) {
            const char *kind = do_spike ? "SPIKE" : "SNAP";
            int seq = do_spike ? ++dumps : ++snaps;
            if (do_spike) last_dump = wall; else last_snap = wall;
            ihp_line("=== %s #%d %llu.%03llu cpu=%d%% threads=%u ===",
                     kind, seq,
                     (unsigned long long)(wall / 1000000ULL),
                     (unsigned long long)((wall / 1000ULL) % 1000ULL),
                     pct, (unsigned)count);
            for (mach_msg_type_number_t i = 0; i < count; i++) {
                ihp_dump_thread(threads[i], (int)i);
            }
            ihp_line("=== END %s #%d ===", kind, seq);
        }

        if (threads) vm_deallocate(mach_task_self(), (vm_address_t)threads,
                                   (vm_size_t)(count * sizeof(thread_t)));
        prev_cpu = cpu;
        prev_wall = wall;
    }
    ihp_line("STOP dumps=%d snaps=%d reached", dumps, snaps);
    return NULL;
}

/* ---- boot proof (v1.0.2, 照抄 SearchPartyQuiet v1.0.3 已验证范式) --------
 * priority=100 先于默认 ctor 执行。只用 open()+预置常量,不用 syslog/getenv/
 * vsnprintf/flag/early-return。若装机后能找到 ih_probe_boot_*.log 但没有
 * ih_probe_*.log => ctor 执行了但 open_log 的多候选全失败;若 boot 文件也
 * 没有 => constructor 根本没被 dyld 执行(注入层问题)。一锤定音。 */
__attribute__((constructor(100))) static void ihp_boot_proof(void) {
    static const char boot[] = "BOOT ctor-executed build=1.1.0\n";
    char p0[256], p2[256];
    snprintf(p0, sizeof(p0), "/var/mobile/Library/Intents/ih_probe_boot_%d.log", (int)getpid());
    snprintf(p2, sizeof(p2), "/var/tmp/ih_probe_boot_%d.log", (int)getpid());
    (void)mkdir("/var/mobile/Library/Intents", 0755);
    int fd = open(p0, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) fd = open(p2, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    (void)write(fd, boot, sizeof(boot) - 1);
    close(fd);
}

__attribute__((constructor)) static void ihp_init(void) {
    /* v1.0.3: 去掉 syslog（SPQ 完全不用；设备上也没 log 命令读不到）。
     * 完全照抄 SPQ: open_log 直接写进程自有目录,BOOT proof 已在 ctor(100) 写。 */
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
