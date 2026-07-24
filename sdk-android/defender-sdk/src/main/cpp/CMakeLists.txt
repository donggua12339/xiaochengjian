cmake_minimum_required(VERSION 3.22.1)
project(xcj_defender C)

# ============= 编译选项 =============
# -O2: 优化(体积 + 性能)
# -fvisibility=hidden: 隐藏非导出符号(防逆向定位)
# -ffunction-sections: 允许链接器去除未用函数
# -fdata-sections: 允许链接器去除未用数据
# -Wall: 警告
# -Wno-unused-parameter: 忽略未用参数警告(JNI 函数签名固定)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
    -O2 \
    -fvisibility=hidden \
    -ffunction-sections \
    -fdata-sections \
    -Wall \
    -Wno-unused-parameter \
")

# Release 模式去除符号表 + strip
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} \
    -Wl,--gc-sections \
    -Wl,--exclude-libs,ALL \
    -Wl,-s \
")

# ============= 源文件 =============
set(DEFENDER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/defender_jni.c
    ${CMAKE_CURRENT_SOURCE_DIR}/self_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/sig_verify.c
    ${CMAKE_CURRENT_SOURCE_DIR}/anti_debug.c
    ${CMAKE_CURRENT_SOURCE_DIR}/anti_frida.c
    ${CMAKE_CURRENT_SOURCE_DIR}/root_check.c
    ${CMAKE_CURRENT_SOURCE_DIR}/integrity.c
    ${CMAKE_CURRENT_SOURCE_DIR}/anti_dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/defender_response.c
    # 方案 A + B + C(v2.1.1 整改)
    ${CMAKE_CURRENT_SOURCE_DIR}/mmap_reader.c
    ${CMAKE_CURRENT_SOURCE_DIR}/signing_block_parser.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hash_calculator.c
    ${CMAKE_CURRENT_SOURCE_DIR}/hash_storage.c
    ${CMAKE_CURRENT_SOURCE_DIR}/self_integrity.c
    ${CMAKE_CURRENT_SOURCE_DIR}/dex_integrity.c
    ${CMAKE_CURRENT_SOURCE_DIR}/trigger_scheduler.c
    ${CMAKE_CURRENT_SOURCE_DIR}/validator_core.c
    ${CMAKE_CURRENT_SOURCE_DIR}/server_gate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/patch_env_detect.c
    ${CMAKE_CURRENT_SOURCE_DIR}/inner_loader.c
    ${CMAKE_CURRENT_SOURCE_DIR}/custom_linker.c
)

# ============= 构建共享库 =============
add_library(xcj_defender SHARED ${DEFENDER_SOURCES})

# ============= 链接库 =============
# log: Android 日志
# android: Android NDK API
# z: zlib(Integrity 模块解压 APK entry / MANIFEST.MF)
target_link_libraries(xcj_defender
    log
    android
    z
    dl
)

# ============= include 目录 =============
target_include_directories(xcj_defender PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
