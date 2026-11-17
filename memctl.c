// memctl.c - 内核级内存读写工具（对接 MemoryDriver_IOCTLhook.kpm）
// 编译: aarch64-linux-android21-clang -O2 -static -o memctl memctl.c
// 用法:
//   memctl pid <包名>                       找 pid
//   memctl base <pid> <模块名>              找模块基址
//   memctl read <pid> <hex地址> <长度>      读内存(hex dump)
//   memctl write <pid> <hex地址> <hex数据>  写内存
//   memctl search <pid> <字符串> [最大字节]  全内存搜索字符串
//   memctl dump <pid> <hex地址> <长度> <文件> dump 到文件
//   memctl dumpsys <pid> <文件>              按 maps dump 所有可读段

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <errno.h>

#define IOCTL_AMM_READ_MEM    0x7E1A
#define IOCTL_AMM_WRITE_MEM   0x7E1B
#define IOCTL_AMM_FIND_PID    0x7E1C
#define IOCTL_AMM_FIND_MODULE 0x7E1D
#define MAX_PROC_NAME_LEN     256

typedef struct {
    uint32_t  pid;
    uintptr_t addr;
    void     *buffer;
    size_t    size;
} COPY_MEMORY;

typedef struct {
    char  proc_name[MAX_PROC_NAME_LEN];
    pid_t result_pid;
} FIND_PID_REQ;

typedef struct {
    uint32_t pid;
    char     module_name[MAX_PROC_NAME_LEN];
    uintptr_t result_addr;
} FIND_MODULE_REQ;

static int g_fd = -1;

static int drv_open(void)
{
    g_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_fd < 0) {
        fprintf(stderr, "socket failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static long drv_read(uint32_t pid, uint64_t addr, void *buf, size_t size)
{
    COPY_MEMORY req;
    memset(&req, 0, sizeof(req));
    req.pid = pid;
    req.addr = addr;
    req.buffer = buf;
    req.size = size;
    return ioctl(g_fd, IOCTL_AMM_READ_MEM, &req);
}

static long drv_write(uint32_t pid, uint64_t addr, const void *buf, size_t size)
{
    COPY_MEMORY req;
    memset(&req, 0, sizeof(req));
    req.pid = pid;
    req.addr = addr;
    req.buffer = (void *)buf;
    req.size = size;
    return ioctl(g_fd, IOCTL_AMM_WRITE_MEM, &req);
}

static pid_t drv_find_pid(const char *name)
{
    FIND_PID_REQ req;
    memset(&req, 0, sizeof(req));
    strncpy(req.proc_name, name, MAX_PROC_NAME_LEN - 1);
    if (ioctl(g_fd, IOCTL_AMM_FIND_PID, &req) < 0)
        return -1;
    return req.result_pid;
}

static uintptr_t drv_find_module(uint32_t pid, const char *mod)
{
    FIND_MODULE_REQ req;
    memset(&req, 0, sizeof(req));
    req.pid = pid;
    strncpy(req.module_name, mod, MAX_PROC_NAME_LEN - 1);
    if (ioctl(g_fd, IOCTL_AMM_FIND_MODULE, &req) < 0)
        return 0;
    return req.result_addr;
}

static void hexdump(const uint8_t *p, size_t n, uint64_t base)
{
    for (size_t i = 0; i < n; i += 16) {
        printf("%012llx  ", (unsigned long long)(base + i));
        for (size_t j = 0; j < 16 && i + j < n; j++)
            printf("%02x ", p[i + j]);
        for (size_t j = (n - i < 16 ? n - i : 16); j < 16; j++)
            printf("   ");
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < n; j++) {
            uint8_t c = p[i + j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("|\n");
    }
}

// 解析 maps 得到可读区间
typedef struct { uint64_t start, end; char perms[8]; char path[256]; } Region;

static int parse_maps(pid_t pid, Region **out)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "open %s failed\n", path); return -1; }

    Region *arr = NULL;
    int cnt = 0, cap = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        uint64_t s, e;
        char perms[8] = {0}, p[256] = {0};
        // 格式: start-end perms offset dev inode path
        int got = sscanf(line, "%llx-%llx %7s %*s %*s %*s %255s",
                         (unsigned long long *)&s, (unsigned long long *)&e, perms, p);
        if (got < 3) continue;
        if (perms[0] != 'r') continue;
        if (cnt == cap) {
            cap = cap ? cap * 2 : 256;
            arr = realloc(arr, cap * sizeof(Region));
        }
        arr[cnt].start = s;
        arr[cnt].end = e;
        strncpy(arr[cnt].perms, perms, 7);
        strncpy(arr[cnt].path, (got >= 4 ? p : ""), 255);
        cnt++;
    }
    fclose(f);
    *out = arr;
    return cnt;
}

static int cmd_search(uint32_t pid, const char *needle, uint64_t maxbytes)
{
    Region *r = NULL;
    int n = parse_maps(pid, &r);
    if (n < 0) return 1;

    size_t nlen = strlen(needle);
    size_t bufsz = 1 << 20;
    uint8_t *buf = malloc(bufsz);
    uint64_t scanned = 0;
    int hits = 0;

    for (int i = 0; i < n; i++) {
        uint64_t addr = r[i].start;
        while (addr < r[i].end) {
            size_t chunk = r[i].end - addr;
            if (chunk > bufsz) chunk = bufsz;
            long got = drv_read(pid, addr, buf, chunk);
            if (got > 0) {
                for (long k = 0; k + (long)nlen <= got; k++) {
                    if (memcmp(buf + k, needle, nlen) == 0) {
                        printf("HIT %012llx  [%s]\n",
                               (unsigned long long)(addr + k),
                               r[i].path[0] ? r[i].path : "anon");
                        if (++hits >= 50) goto done;
                    }
                }
                scanned += got;
            }
            addr += chunk;
            if (maxbytes && scanned >= maxbytes) goto done;
        }
    }
done:
    printf("--- scanned %llu bytes, %d hits, %d regions ---\n",
           (unsigned long long)scanned, hits, n);
    free(buf); free(r);
    return 0;
}

static int cmd_dumpsys(uint32_t pid, const char *outfile)
{
    Region *r = NULL;
    int n = parse_maps(pid, &r);
    if (n < 0) return 1;

    FILE *out = fopen(outfile, "wb");
    if (!out) { fprintf(stderr, "open %s failed\n", outfile); return 1; }

    size_t bufsz = 1 << 20;
    uint8_t *buf = malloc(bufsz);
    uint64_t total = 0;

    // 写头部索引
    for (int i = 0; i < n; i++)
        fprintf(out, "# %012llx-%012llx %s %s\n",
                (unsigned long long)r[i].start, (unsigned long long)r[i].end,
                r[i].perms, r[i].path);

    for (int i = 0; i < n; i++) {
        uint64_t addr = r[i].start;
        while (addr < r[i].end) {
            size_t chunk = r[i].end - addr;
            if (chunk > bufsz) chunk = bufsz;
            long got = drv_read(pid, addr, buf, chunk);
            if (got > 0) { fwrite(buf, 1, got, out); total += got; }
            addr += chunk;
        }
    }
    fclose(out);
    printf("dumped %llu bytes from %d regions -> %s\n",
           (unsigned long long)total, n, outfile);
    free(buf); free(r);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "用法:\n"
            "  memctl pid <包名>\n"
            "  memctl base <pid> <模块名>\n"
            "  memctl read <pid> <hex地址> <长度>\n"
            "  memctl write <pid> <hex地址> <hex数据>\n"
            "  memctl search <pid> <字符串> [最大字节]\n"
            "  memctl dumpsys <pid> <输出文件>\n");
        return 1;
    }

    if (drv_open() < 0) return 1;

    const char *cmd = argv[1];

    if (!strcmp(cmd, "pid") && argc >= 3) {
        pid_t p = drv_find_pid(argv[2]);
        printf("%d\n", p);
        return p > 0 ? 0 : 1;
    }
    if (!strcmp(cmd, "base") && argc >= 4) {
        uintptr_t a = drv_find_module((uint32_t)atoi(argv[2]), argv[3]);
        printf("0x%llx\n", (unsigned long long)a);
        return a ? 0 : 1;
    }
    if (!strcmp(cmd, "read") && argc >= 5) {
        uint32_t pid = atoi(argv[2]);
        uint64_t addr = strtoull(argv[3], NULL, 16);
        size_t len = (size_t)strtoull(argv[4], NULL, 0);
        uint8_t *buf = malloc(len);
        long got = drv_read(pid, addr, buf, len);
        if (got <= 0) { fprintf(stderr, "read failed (%ld)\n", got); return 1; }
        hexdump(buf, (size_t)got, addr);
        free(buf);
        return 0;
    }
    if (!strcmp(cmd, "write") && argc >= 5) {
        uint32_t pid = atoi(argv[2]);
        uint64_t addr = strtoull(argv[3], NULL, 16);
        const char *hex = argv[4];
        size_t n = strlen(hex) / 2;
        uint8_t *buf = malloc(n);
        for (size_t i = 0; i < n; i++) {
            unsigned v;
            sscanf(hex + i * 2, "%2x", &v);
            buf[i] = (uint8_t)v;
        }
        long r = drv_write(pid, addr, buf, n);
        printf("write ret=%ld (%zu bytes)\n", r, n);
        free(buf);
        return r > 0 ? 0 : 1;
    }
    if (!strcmp(cmd, "search") && argc >= 4) {
        uint32_t pid = atoi(argv[2]);
        uint64_t maxb = (argc >= 5) ? strtoull(argv[4], NULL, 0) : 0;
        return cmd_search(pid, argv[3], maxb);
    }
    if (!strcmp(cmd, "dumpsys") && argc >= 4) {
        return cmd_dumpsys((uint32_t)atoi(argv[2]), argv[3]);
    }

    fprintf(stderr, "未知命令或参数不足\n");
    return 1;
}
