/**
 * x8_anti_fart.c - X8 FART 脱壳扫描(玄甲 v1.0 P2)
 *
 * FART(ArtMethod traversal)原理:遍历所有 ArtMethod 并 invoke,
 * 触发 JIT 编译 → 内存中产生完整 DEX 镜像 → dump 到文件。
 *
 * 检测维度:
 *  A. /data/data/<pkg>/ 下出现异常 .dex 文件(正常 app 不应有散落 dex)
 *  B. /proc/self/maps 中出现额外 dex/oat 映射(非 /data/app/ 路径)
 *  C. /proc/self/fd 中打开的 .dex 文件数量异常(FART dump 时会 open)
 *  D. /data/local/tmp/ 下出现 .dex(FART 默认输出目录)
 *
 * 返回:可疑计数(0=干净)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

#define DEFENDER_TAG "X8AntiFart"
#include "defender_log.h"
#include "x4_svc.h"

static char g_pkg_dir[256] = {0};

void x8_init(const char *pkg_name) {
    if (pkg_name) {
        snprintf(g_pkg_dir, sizeof(g_pkg_dir), "/data/data/%s", pkg_name);
    }
}

/**
 * A: 检测 app 私有目录下异常 .dex 文件
 * 正常 app 的 dex 在 /data/app/.../base.apk 内,不应散落在 data 目录
 */
static int check_abnormal_dex_in_data(void) {
    if (g_pkg_dir[0] == '\0') return 0;

    int count = 0;
    DIR *d = opendir(g_pkg_dir);
    if (!d) return 0;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        size_t len = strlen(ent->d_name);
        if (len > 4 && strcmp(ent->d_name + len - 4, ".dex") == 0) {
            /* 排除已知的合法 dex(如 code_cache 中的 JIT 产物) */
            char full[512];
            snprintf(full, sizeof(full), "%s/%s", g_pkg_dir, ent->d_name);
            struct stat st;
            if (stat(full, &st) == 0 && st.st_size > 1024) {
                LOGE("X8-A: 异常 .dex 在 data 目录");
                count++;
            }
        }
    }
    closedir(d);

    /* 检查子目录 code_cache/、cache/ 下的异常大 dex(>500KB 可能是 dump) */
    const char *subdirs[] = {"code_cache", "cache", "files"};
    for (int i = 0; i < 3; i++) {
        char subdir[300];
        snprintf(subdir, sizeof(subdir), "%s/%s", g_pkg_dir, subdirs[i]);
        DIR *sd = opendir(subdir);
        if (!sd) continue;
        while ((ent = readdir(sd)) != NULL) {
            size_t len = strlen(ent->d_name);
            if (len > 4 && strcmp(ent->d_name + len - 4, ".dex") == 0) {
                char full[512];
                snprintf(full, sizeof(full), "%s/%s", subdir, ent->d_name);
                struct stat st;
                if (stat(full, &st) == 0 && st.st_size > 512 * 1024) {
                    LOGE("X8-A: 大 .dex 在 %s 子目录(疑似 dump)", subdirs[i]);
                    count++;
                }
            }
        }
        closedir(sd);
    }
    return count;
}

/**
 * B: maps 中检测非标准路径的 .dex/.oat 映射
 */
static int check_maps_abnormal_dex(void) {
    int fd = x4_svc_openat(AT_FDCWD, OBF("/proc/self/maps"), O_RDONLY, 0);
    if (fd < 0) return 0;

    char buf[65536];
    ssize_t total = 0, n;
    while ((n = x4_svc_read(fd, buf + total, sizeof(buf) - 1 - (size_t)total)) > 0) {
        total += n;
        if ((size_t)total >= sizeof(buf) - 1) break;
    }
    x4_svc_close(fd);
    buf[total] = '\0';

    int count = 0;
    char *line = buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        /* 找含 .dex 或 .oat 的映射行 */
        if (strstr(line, ".dex") || strstr(line, ".oat")) {
            /* 排除合法路径:/data/app/ 和 /system/ */
            if (!strstr(line, "/data/app/") && !strstr(line, "/system/") &&
                !strstr(line, "/apex/") && !strstr(line, "/product/")) {
                /* 非标准路径的 dex/oat 映射 = 可疑 */
                if (strstr(line, "/data/data/") || strstr(line, "/data/local/") ||
                    strstr(line, "/sdcard/")) {
                    LOGE("X8-B: maps 异常 dex/oat 映射");
                    count++;
                }
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    return count;
}

/**
 * C: /proc/self/fd 中打开的 .dex 文件数量
 */
static int check_fd_dex_count(void) {
    int dir_fd = x4_svc_openat(AT_FDCWD, OBF("/proc/self/fd"), O_RDONLY | O_DIRECTORY, 0);
    if (dir_fd < 0) return 0;

    int dex_count = 0;
    char buf[4096];
    ssize_t n;
    /* 用 getdents 遍历(简化:读目录内容) */
    DIR *d = fdopendir(dir_fd);
    if (!d) { x4_svc_close(dir_fd); return 0; }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char link_path[256];
        char target[256];
        snprintf(link_path, sizeof(link_path), "/proc/self/fd/%s", ent->d_name);
        ssize_t len = readlink(link_path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            size_t tlen = strlen(target);
            if (tlen > 4 && strcmp(target + tlen - 4, ".dex") == 0) {
                /* 排除 /data/app/ 内的(系统加载) */
                if (!strstr(target, "/data/app/")) {
                    dex_count++;
                }
            }
        }
    }
    closedir(d);

    if (dex_count > 2) {
        LOGE("X8-C: fd 中 %d 个非标准 .dex(疑似 FART dump)", dex_count);
        return 1;
    }
    return 0;
}

/**
 * D: /data/local/tmp/ 下 .dex 文件(FART 默认输出)
 */
static int check_tmp_dex(void) {
    DIR *d = opendir("/data/local/tmp");
    if (!d) return 0;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        size_t len = strlen(ent->d_name);
        if (len > 4 && strcmp(ent->d_name + len - 4, ".dex") == 0) {
            LOGE("X8-D: /data/local/tmp 存在 .dex(FART 输出)");
            count++;
        }
    }
    closedir(d);
    return count > 0 ? 1 : 0;
}

/**
 * X8 综合检测入口
 * @return 可疑计数(0=干净,≥2=高度疑似 FART)
 */
int x8_anti_fart_check(void) {
    int score = 0;
    score += check_abnormal_dex_in_data();
    score += check_maps_abnormal_dex();
    score += check_fd_dex_count();
    score += check_tmp_dex();
    return score;
}
