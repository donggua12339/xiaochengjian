cmake_minimum_required(VERSION 3.22.1)
project(xcj_defender C)

# T4 DEX 字符串解密开关(ADR 0090):需先跑 injector encrypt-strings 生成 t4_str_key.h
option(T4_ENABLED "Enable T4 DEX string decryption (requires t4_str_key.h)" OFF)

# 多态检测 seed:每次构建随机,anti_frida 检测顺序随 seed 变化
string(TIMESTAMP _ts "%S%M")
math(EXPR _seed "0x${_ts} ^ 0x5A3C")
add_compile_definitions(ANTI_FRIDA_POLY_SEED=${_seed})

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

# Release 模式优化;strip 交给 Gradle stripReleaseDebugSymbols(release 管线保证),
# 不在此处 -Wl,-s——POST_BUILD 的 patch_vm_self_ref.py 需要 .symtab 里的
# __start_vmself_code/__stop_vmself_code 符号定位自引用 CRC 范围(ADR 0098 P0-C)。
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -O2")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} \
    -Wl,--gc-sections \
    -Wl,--exclude-libs,ALL \
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
    # T4 DEX 字符串解密(ADR 0090) + VM 引擎(T2 VMP)
    ${CMAKE_CURRENT_SOURCE_DIR}/t4_str_decrypt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vm_engine.c
    # X8 FART 脱壳扫描 + X9 ODEX 修补检测
    ${CMAKE_CURRENT_SOURCE_DIR}/x8_anti_fart.c
    ${CMAKE_CURRENT_SOURCE_DIR}/x9_odex_detect.c
    # T3 字符串分段散列(天衍)
    ${CMAKE_CURRENT_SOURCE_DIR}/t3_segment_str.c
    # X4-0 基建(ADR 0093):svc 原语 + 自实现字符串 + 守护线程框架
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_svc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_str.c
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_daemon.c
    # X4-1 L1 反注入(ADR 0093):注入SO/可执行段/ptrace 检测 + JNI 桥接
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_anti_inject.c
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_anti_debug.c
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_anti_dump.c
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_smc.c
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_integrity.c
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_jni.c
    # X4 响应链(ADR 0093,Q1-Q5 定稿):三通道 + 衰减 + dry-run + 回滚
    ${CMAKE_CURRENT_SOURCE_DIR}/strong_evidence.c
    ${CMAKE_CURRENT_SOURCE_DIR}/strong_evidence_classloader.c
    ${CMAKE_CURRENT_SOURCE_DIR}/weak_detector.c
    ${CMAKE_CURRENT_SOURCE_DIR}/weak_detector_jni.c
    ${CMAKE_CURRENT_SOURCE_DIR}/score_engine.c
    ${CMAKE_CURRENT_SOURCE_DIR}/response_chain.c
    ${CMAKE_CURRENT_SOURCE_DIR}/config_loader.c
    ${CMAKE_CURRENT_SOURCE_DIR}/config_loader_jni.c
    ${CMAKE_CURRENT_SOURCE_DIR}/dry_run.c
    ${CMAKE_CURRENT_SOURCE_DIR}/telemetry.c
    ${CMAKE_CURRENT_SOURCE_DIR}/auto_rollback.c
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_core.c
    # GC 根巡检(ADR 0098 P0-D,Virbox sub_29397C 反哺)
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_gc_roots.c
    # X4 占位 stub(toast/telemetry,Q5 灰度期补真机 JNI 实现)
    ${CMAKE_CURRENT_SOURCE_DIR}/x4_stubs.c
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
    set(HIKARI_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/../../../scripts/native_cff.py)
    foreach(src ${DEFENDER_SOURCES})
        get_filename_component(fname ${src} NAME)
        set(gen ${OBF_GEN_DIR}/${fname})
        set(num_obf_tmp ${OBF_GEN_DIR}/${fname}.num_obf)
        # Hikari 数字混淆(ADR 0094)→ X1 字符串加密,两步串联
        set(_obf_cmd ${Python3_EXECUTABLE} ${OBF_SCRIPT} --transform ${num_obf_tmp} ${gen})
        if(OBF_SEED)
            list(APPEND _obf_cmd --seed ${OBF_SEED})
        endif()
        add_custom_command(
            OUTPUT ${gen}
            COMMAND ${Python3_EXECUTABLE} ${HIKARI_SCRIPT} --number-obf ${src} ${num_obf_tmp}
            COMMAND ${_obf_cmd}
            DEPENDS ${src} ${OBF_SCRIPT} ${HIKARI_SCRIPT}
            COMMENT "Hikari+X1 transform: ${fname}"
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

# T4 编译开关(ADR 0090)
if(T4_ENABLED)
    target_compile_definitions(xcj_defender PRIVATE T4_ENABLED=1)
endif()

# ============= include 目录 =============
target_include_directories(xcj_defender PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# ============= VM 自引用 CRC 写入(ADR 0098 P0-C)=============
# 链接后按 .symtab 的 __start_/__stop_vmself_code 定位 dispatch 区段算 CRC-32,
# 写入 .rodata 占位符。VM 引擎未链入(被 gc-sections 回收)时脚本优雅跳过。
set(VM_SELFREF_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/../../../scripts/patch_vm_self_ref.py)
if(Python3_Interpreter_FOUND AND EXISTS ${VM_SELFREF_SCRIPT})
    add_custom_command(TARGET xcj_defender POST_BUILD
        COMMAND ${Python3_EXECUTABLE} ${VM_SELFREF_SCRIPT} $<TARGET_FILE:xcj_defender>
        COMMENT "VM self-ref: 写入 dispatch CRC32"
        VERBATIM
    )
else()
    message(WARNING "VM self-ref: 未找到 Python3 或 patch_vm_self_ref.py,自引用 CRC 不写入(运行时跳过)")
endif()

# ============= Hikari CFF 参数生成(ADR 0094,每构建随机化)=============
# native_cff.py --gen-params 生成 cff_params.h(CFF 状态表+LCG) + x0_derive.h(密钥派生材料)。
# 依赖 x0_key.h(密钥)和 hikari.json(配置)。每构建随机,二进制不可复现。
set(HIKARI_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/../../../scripts/native_cff.py)
set(HIKARI_JSON   ${CMAKE_CURRENT_SOURCE_DIR}/../../../scripts/hikari.json)
set(CFF_PARAMS_H  ${CMAKE_CURRENT_SOURCE_DIR}/cff_params.h)
set(X0_DERIVE_H   ${CMAKE_CURRENT_SOURCE_DIR}/x0_derive.h)
set(X0_KEY_H      ${CMAKE_CURRENT_SOURCE_DIR}/x0_key.h)

if(Python3_Interpreter_FOUND AND EXISTS ${HIKARI_SCRIPT})
    add_custom_command(
        OUTPUT ${CFF_PARAMS_H} ${X0_DERIVE_H}
        COMMAND ${Python3_EXECUTABLE} ${HIKARI_SCRIPT} --gen-params --config ${HIKARI_JSON}
        DEPENDS ${HIKARI_SCRIPT} ${HIKARI_JSON} ${X0_KEY_H}
        COMMENT "Hikari: 生成 CFF 随机参数 + 密钥派生材料"
        VERBATIM
    )
else()
    message(WARNING "Hikari: 未找到 Python3 或 native_cff.py,CFF 参数不重新生成(使用已有)")
endif()

# ============= X0-3 stub loader(CFF 保护密钥派生,ADR 0094)=============
# 正常 System.loadLibrary 加载;JNI_OnLoad 里自举:解密嵌入载荷 → memfd →
# android_dlopen_ext → 手动调载荷 JNI_OnLoad。
# 密钥不再明文存储,改为 CFF 保护的运行时派生(xcj_check_abi_compat)。
add_library(xcj_loader SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/xcj_loader.c
    ${CMAKE_CURRENT_SOURCE_DIR}/custom_linker.c
)
target_link_libraries(xcj_loader log android dl)
target_include_directories(xcj_loader PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
if(Python3_Interpreter_FOUND AND EXISTS ${HIKARI_SCRIPT})
    add_dependencies(xcj_loader cff_params_gen)
    add_custom_target(cff_params_gen DEPENDS ${CFF_PARAMS_H} ${X0_DERIVE_H})
endif()
