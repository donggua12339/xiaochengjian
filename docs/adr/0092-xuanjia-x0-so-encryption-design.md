# ADR 0092 · 玄甲 X0:外壳 SO 加密设计(藏资源 + 全 native 自举 + 构建期密钥)

- 状态:**accepted**(2026-07-26 真机验证通过:bootstrap rc=0,四步构建流水线稳定,方案 A 哈希匹配)
- 日期:2026-07-24
- 决策者:小城笺项目
- 层次:功能 / 安全
- 关联:ADR 0088(defender-sdk)、0089(加固引擎 v0.1-v0.3:inner SO + 自实现 Linker + VMP)、0091(玄甲/天衍产品线,§3.1 SO 加密管线);本 ADR 细化 0091 的 X0 槽位
- 上游事实:看雪 thread-287254(yuuki 自定义 Linker 与 SO 加固:RC4 + 魔数 + 藏资源)

## 背景

玄甲 v1.0 路线图 P0 含 X0「外壳 SO 本体加密」:让 `libxcj_defender.so` 不以明文落地、不能被 MT/NP 一键静态提取。0091 §3.1 已定"RC4 加密 → 藏资源 → memfd 加载"方向;本 ADR 把**威胁模型、自举架构、密文隐藏位置、密钥管理、与 inner 的关系、实现排序**逐项钉死(2026-07-24 设计拷问六分支共识)。

## 决策

### 1. 威胁模型与目标(够用即止)
- X0 目标 = **抬门槛 / 逼转动态**:.so 不以明文落地、抗 MT/NP 一键静态提取。**不追求抗专业逆向**——那是 X4 五层反动态 + 天衍 VMP/迷宫 的职责。
- 故 RC4(弱加密)**够用即止**,不在加密强度上过度投入;真正纵深在动态对抗层。X0 是"门禁"不是"保险库",实现求精简,重心后续给 X4。

### 2. 自举架构:全 native stub
- 外壳 .so 被加密后,系统须先加载一个**不加密的极小 stub** `libxcj_loader.so`(正常 `System.loadLibrary`)发起解密——loader 不能在它要加载的密文壳里(鸡生蛋)。
- **密文/明文全程在 native,Java 不经手**(选"全 native"而非"Java 读密文"):stub 自己 mmap 本 APK 找密文。
- stub 流程:定位密文(§3)→ RC4 解密(`so_cipher.h`)→ `memfd_create` 写解密 .so → `android_dlopen_ext(ANDROID_DLEXT_USE_LIBRARY_FD)` 加载 → `dlsym` 出外壳 `JNI_OnLoad` **手动调用**(注册 native 方法 + 起守护线程 + self_integrity 初始化)→ `memset` 清零解密缓冲、关 fd。
- **两条硬约束**:
  1. 必须 **memfd**,不能解密成临时文件再 `System.load`(否则明文落地,违背 §1)。
  2. `android_dlopen_ext` 加载的 .so,系统**不自动调其 `JNI_OnLoad`**(那是 `System.loadLibrary` 路径才有)→ 必须 dlsym 后手动调,否则 native 方法不注册、守护线程不起。

### 3. 密文隐藏位置:(i) 优先 + (ii) 兜底,loader 机制无关
- **优先 (i)**:追加到一个现有 **STORED(未压缩)** 资源条目尾部(隐蔽,无新文件)。
- **兜底 (ii)**:加一个**专用 STORED asset**(无害命名,如伪装字体/数据文件),当 APK 无合适 STORED 资源时。
- **loader 与机制无关**:复用 `integrity.c` 的 zip 遍历,**扫各 zip 条目找尾部带 `so_cipher` 魔数框架 `[密文][MAGIC "XCJSO1"][len u32 LE]` 的条目**,解密后**校验 `\x7fELF` 头**(确认是 .so,把误报压到近零)。(i)/(ii) 尾部都符合框架,loader 一套逻辑通吃。
- **Packer 端**:(i) 改 local header + 中央目录的 CRC32/compressed/uncompressed size;(ii) 加新条目(加条目 ≪ 改现有条目 CRC,更省事)。
- **已否决 (iv)「追加到整个 APK 文件尾(EOCD 之后)」**:2026-07-24 实测,demo APK 尾部追加 8KB(不含 zip 魔数)后 `adb install` 报 `INSTALL_PARSE_FAILED_NOT_APK / Failed to load asset path`——Android AssetManager 拒绝 EOCD 之后的尾部杂数据。"零 zip 解析、文件尾追加"路线被 Android 解析器否决。
- 注:RC4 密文为伪随机,约 0.01%/构建 概率含 zip 魔数(`PK\x05\x06` 等)致"倒扫定位"扫错;**必须规避**(加密后扫密文,含 zip 魔数则换 nonce/重加密直到干净)。

### 4. 密钥管理:构建期参数 + 玄甲强制密钥 + 一键 keygen
- 密钥是**构建期参数**,编进 stub 并用 **X1 `OBF()` 混淆**(不当明文串)。`so_cipher_extract(..., key, klen, ...)` 本就设计为"密钥作参数传入"。
- **玄甲(开源免费)**:**强制开发者提供密钥**(不留公开默认密钥——开源仓库里的默认密钥等于公开);SDK 内置**一键 keygen** 生成随机密钥(不麻烦又增安全)。缺密钥 → 构建报错,不回退默认。
- **天衍(付费闭源 Packer)**:**自动每应用生成随机强密钥**,混淆注入,全自动。
- 边界:密钥在 stub(明文加载)里,即使 X1 混淆,**专业逆向仍可提取**——合 §1(抬门槛即可);抗逆向靠天衍 VMP/迷宫保护 stub。

### 5. 与 inner(SO 中藏 SO)的关系:互补,两层都保留
- **X0 抗静态提取**(外壳 .so 不明文落地);**inner 抗运行时 dump**(核心校验 `verify_hash` 已 VMP,在独立 memfd,外壳被 dump 也拿不到它)。两者挡不同威胁,**不冗余**。
- 运行时三层链:`stub`(明文)→ `外壳`(RC4/memfd)→ `inner`(XOR/memfd);inner 双重保护。
- inner 用 XOR(弱)但合 §1(还叠 VMP + memfd);三层链多两次早期 memfd 加载,微小开销可接受。inner 那套(inner_defender/inner_loader/custom_linker/vm_engine)已写好并真机验证,**全保留**。

### 6. 实现排序
1. **先修 X1 的 python**(NDK CMake 找不到 Python → X1 当前构建里不生效,已提交引擎"空转"):修法为从 Gradle 传 `-DPython3_EXECUTABLE`,或把 transform 挪进 Gradle task(后者更稳)。**这是 X0 密钥混淆的前置**(X0-3 靠 X1 混淆 stub 里的密钥;X1 不生效则密钥明文)。
2. **再实现 X0**:X0-2(Packer 按 (i)/(ii) 嵌入)+ X0-3(stub loader + memfd + 手动 JNI_OnLoad)+ 一键 keygen。
3. **然后主力 X4 五层反动态**(玄甲差异化核心;§1 threat model 把重担压在这)。
4. **穿插**:Linker 抹 Section Header + 多 PT_DYNAMIC 迷惑(看雪启发,低成本)、VMP handler 洗牌、X2 日志保护 / X3 生命周期检测。

## 已就绪资产
- `so_cipher.h` / `so_cipher.py`:RC4 + 魔数框架(尾部 `[密文][XCJSO1][len]`),host 交叉验证 ALL PASS(2026-07-24,X0-1 已提交 `947e6f4`)。`so_cipher_extract` 即 §3 的"扫尾框架解密";`--encrypt` CLI 供 Packer;待加 `--genkey`(§4)与"密文含 zip 魔数则重加密"(§3 注)。

## 风险与未决
- (i) 对**任意用户 APK** 的稳健性取决于能否找到合适 STORED 资源;找不到走 (ii)。Packer 需实现"找 STORED 条目 + 改 CRC"与"加 asset"两条路径。
- X0-3 手动调外壳 `JNI_OnLoad` 的时机/线程需实测(守护线程、self_integrity 初始化依赖主线程语义)。
- RC4 强度非目标;若未来要抬高加密档,换算法即可(`so_cipher` 接口不变)。
