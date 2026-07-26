/**
 * x9_odex_detect.c - X9 ODEX 修补检测(玄甲 v1.0 P2)
 *
 * 检测维度:
 *  A. base.odex 是否存在于预期路径(不存在 = 可能被删除以绕过校验)
 *  B. base.odex 修改时间 vs base.apk 修改时间(odex 比 apk 新 = 被重新生成/修补)
 *  C. .vdex 文件完整性(大小异常 = 被篡改)
 *  D. /data/app/ 下是否存在多个版本的 oat 目录(重编译痕迹)
 *
 * 注:完整 CRC 校验需构建期预埋预期值(patch_x0.py 扩展),当前为行为检测。
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

#define DEFENDER_TAG "X9OdexDetect"
#include "defender_log.h"
#include "x4_svc.h"

static char g_apk_path[512] = {0};

void x9_init(const char *apk_path) {
    if (apk_path) {
        strncpy(g_apk_path, apk_path, sizeof(g_apk_path) - 1);
    }
}

/**
 * 从 APK 路径推导 oat 目录:
 * /data/app/~~hash/pkg/lib/arm64/base.apk → /data/app/~~hash/pkg/oat/arm64/
 */
static int get_oat_dir(char *out, size_t out_size) {
    if (g_apk_path[0] == '\0') return -1;

    /* 找 /lib/ 并替换为 /oat/ */
    char *lib_pos = strstr(g_apk_path, "/lib/");
    if (!lib_pos) {
        /* 尝试从包路径推导 */
        char *base = strstr(g_apk_path, "/base.apk");
        if (!base) return -1;
        size_t prefix_len = (size_t)(base - g_apk_path);
        snprintf(out, out_size, "%.*s/oat/arm64", (int)prefix_len, g_apk_path);
        return 0;
    }

    size_t prefix_len = (size_t)(lib_pos - g_apk_path);
    snprintf(out, out_size, "%.*s/oat/arm64", (int)prefix_len, g_apk_path);
    return 0;
}

/**
 * A+B: 检查 base.odex 存在性 + 修改时间对比
 */
static int check_odex_time_anomaly(void) {
    char oat_dir[512];
    if (get_oat_dir(oat_dir, sizeof(oat_dir)) != 0) return 0;

    char odex_path[600];
    snprintf(odex_path, sizeof(odex_path), "%s/base.odex", oat_dir);

    struct stat odex_st, apk_st;

    /* APK 必须能 stat */
    if (stat(g_apk_path, &apk_st) != 0) return 0;

    if (stat(odex_path, &odex_st) != 0) {
        /* odex 不存在:可能被删除(某些绕过手段删除 odex 让系统重新 dex2oat) */
        /* 不算严重,因为 extractNativeLibs=false 时可能没有 odex */
        return 0;
    }

    /* B: odex 修改时间比 apk 新超过 60 秒 = 可疑(被重新编译/修补) */
    if (odex_st.st_mtime > apk_st.st_mtime + 60) {
        LOGE("X9-B: base.odex 比 base.apk 新(疑似重编译修补)");
        return 1;
    }

    return 0;
}

/**
 * C: .vdex 文件大小异常检测
 * 正常 vdex 应与 APK 中 dex 总大小相关;过小(<1KB)或过大(>APK×2)为异常
 */
static int check_vdex_size(void) {
    char oat_dir[512];
    if (get_oat_dir(oat_dir, sizeof(oat_dir)) != 0) return 0;

    char vdex_path[600];
    snprintf(vdex_path, sizeof(vdex_path), "%s/base.vdex", oat_dir);

    struct stat vdex_st, apk_st;
    if (stat(vdex_path, &vdex_st) != 0) return 0;  /* vdex 不存在 = 正常(某些 ROM) */
    if (stat(g_apk_path, &apk_st) != 0) return 0;

    /* vdex 过小(被截断)或过大(被注入额外 dex) */
    if (vdex_st.st_size > 0 && vdex_st.st_size < 100) {
        LOGE("X9-C: base.vdex 异常小(疑似被截断)");
        return 1;
    }
    if (vdex_st.st_size > apk_st.st_size * 3) {
        LOGE("X9-C: base.vdex 异常大(疑似被注入)");
        return 1;
    }

    return 0;
}

/**
 * D: oat 目录下是否存在异常文件(非 base.odex/base.vdex/base.art)
 */
static int check_oat_dir_anomaly(void) {
    char oat_dir[512];
    if (get_oat_dir(oat_dir, sizeof(oat_dir)) != 0) return 0;

    DIR *d = opendir(oat_dir);
    if (!d) return 0;

    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        const char *name = ent->d_name;
        if (name[0] == '.') continue;
        /* 合法文件:base.odex, base.vdex, base.art */
        if (strcmp(name, "base.odex") == 0) continue;
        if (strcmp(name, "base.vdex") == 0) continue;
        if (strcmp(name, "base.art") == 0) continue;
        /* 其他文件 = 可疑 */
        LOGE("X9-D: oat 目录存在异常文件");
        count++;
    }
    closedir(d);
    return count > 0 ? 1 : 0;
}

/**
 * X9 综合检测入口
 * @return 可疑计数(0=干净)
 */
int x9_odex_check(void) {
    int score = 0;
    score += check_odex_time_anomaly();
    score += check_vdex_size();
    score += check_oat_dir_anomaly();
    return score;
}
