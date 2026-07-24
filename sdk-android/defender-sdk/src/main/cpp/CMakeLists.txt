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
    # X4-0 基建(ADR 0093):svc 原语 + 自实现字符串 + 守护线程框架
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_svc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_str.c
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_daemon.c
    # X4-1 L1 反注入(ADR 0093):注入SO/可执行段/ptrace 检测 + JNI 桥接
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_anti_inject.c
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_jni.c
)

# ============= X1 字符串多态加密(构建期代码生成)=============
# 源码写 OBF("明文") 保持可读;构建期 obfstr_poly.py 扫描替换为 _OBF_USE(密文),
# 编译生成副本 → .rodata 无明文、密文每构建随机,抗 MT/NP 一键静态解密。
# 详见 docs/PRODUCT_XUANJIA_TIANYAN.md §5 + ADR 0091 §3.2。
# 找 Python(构建期跑 obfstr_poly.py):优先用 Gradle 传入的 Python3_EXECUTABLE,
# 否则 find_program 显式找——优先 python(真解释器),避开 WindowsApps 的 python3 残桩;
# NDK 的 find_package(Python3) 在该环境会失败,故不用它。
if(NOT DEFINED Python3_EXECUTABLE OR Python3_EXECUTABLE STREQUAL "")
    find_program(Python3_EXECUTABLE NAMES python python.exe python3 python3.exe)
endif()
if(Python3_EXECUTABLE)
    set(Python3_Interpreter_FOUND TRUE)
else()
    set(Python3_Interpreter_FOUND FALSE)
endif()
set(OBF_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/../../../scripts/obfstr_poly.py)
set(OBF_GEN_DIR ${CMAKE_BINARY_DIR}/obf_src)
set(OBF_SEED "" CACHE STRING "X1 字符串加密随机种子(空=每构建 os.urandom 随机)")

if(Python3_Interpreter_FOUND AND EXISTS ${OBF_SCRIPT})
    file(MAKE_DIRECTORY ${OBF_GEN_DIR})
    set(DEFENDER_SOURCES_FINAL "")
    foreach(src ${DEFENDER_SOURCES})
        get_filename_component(fname ${src} NAME)
        set(gen ${OBF_GEN_DIR}/${fname})
        set(_obf_cmd ${Python3_EXECUTABLE} ${OBF_SCRIPT} --transform ${src} ${gen})
        if(OBF_SEED)
            list(APPEND _obf_cmd --seed ${OBF_SEED})
        endif()
        add_custom_command(
            OUTPUT ${gen}
            COMMAND ${_obf_cmd}
            DEPENDS ${src} ${OBF_SCRIPT}
            COMMENT "X1 obfstr transform: ${fname}"
            VERBATIM
        )
        list(APPEND DEFENDER_SOURCES_FINAL ${gen})
    endforeach()
else()
    # 无 Python 或脚本缺失:回退原始源码(OBF() 开发态=明文,可编译但不混淆)
    message(WARNING "X1: 未找到 Python3 或 obfstr_poly.py,字符串加密跳过(明文编译)")
    set(DEFENDER_SOURCES_FINAL ${DEFENDER_SOURCES})
endif()

# ============= 构建共享库 =============
add_library(xcj_defender SHARED ${DEFENDER_SOURCES_FINAL})

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

# ============= X0-3 stub loader(原型,不加密的小 .so)=============
# 正常 System.loadLibrary 加载;JNI_OnLoad 里自举:解密嵌入载荷 → memfd →
# android_dlopen_ext → 手动调载荷 JNI_OnLoad。原型载荷为 x0test(见 x0test_enc.h)。
add_library(xcj_loader SHARED ${CMAKE_CURRENT_SOURCE_DIR}/xcj_loader.c)
target_link_libraries(xcj_loader log android dl)
target_include_directories(xcj_loader PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
