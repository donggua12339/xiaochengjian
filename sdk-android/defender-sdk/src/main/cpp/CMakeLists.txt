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
)

# ============= 构建共享库 =============
add_library(xcj_defender SHARED ${DEFENDER_SOURCES})

# ============= 链接库 =============
# log: Android 日志
# android: Android NDK API
target_link_libraries(xcj_defender
    log
    android
)

# ============= include 目录 =============
target_include_directories(xcj_defender PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
