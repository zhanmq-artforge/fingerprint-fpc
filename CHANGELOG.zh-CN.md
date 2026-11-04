# 更新日志 (CHANGELOG)

本项目的全部核心更新记录均遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/) 规范，
并严格遵守 [语义化版本 2.0.0 (Semantic Versioning)](https://semver.org/lang/zh-CN/) 标准。

[English](CHANGELOG.md) | [简体中文](CHANGELOG.zh-CN.md)

---

## [1.0.0] - 2026-11-04

### 🚀 首个正式生产发布版本：基于 `fingerprint-ocv` 的全量纯 Rust 架构重构

#### ⚡ 异步并发与调度模型革新
* **纯安全 Rust 全量重写**：彻底废弃易崩溃的 C++17 代码库、不稳定的自制 `jinx` 协程引擎以及裸 C `libdbus-1` 回调体系。完全基于 **Tokio** 与 **zbus 5** 现代化异步体系重构，严格遵循 Google 开源 Rust 代码规范。
* **异步 Worker 线程饥饿消除**：将重度图像增强预处理、2x 双线性插值、粗细两阶段网格搜索（NCC）及滑动窗口 MSSIM 相似度比对完整剥离至 `tokio::task::spawn_blocking` 独立线程池中执行，彻底杜绝 Tokio 异步调度器延迟抖动。
* **无锁化瞬时任务取消**：使用原子布尔标记 `cancel_token`（`Arc<AtomicBool>`）替代传统互斥锁死等机制。在收到外部取消信号时毫秒级无锁返回，传感器反布防指令交由后台独立协程异步调度，消除 D-Bus 接口响应卡顿。
* **D-Bus 按需激活（Bus Activation）与空闲休眠**：新增 `--idle-timeout`（默认 30 秒）参数与 `/usr/share/dbus-1/system-services/net.reactivated.Fprint.service` 描述符。闲置超时自动释放 USB 设备并退出，有验证请求时 50 毫秒内瞬间拉起，兼顾极低待机功耗。

#### 🛡️ 高可用（HA）架构与硬件状态机自愈
* **动态生命周期管理器 (`FpcUsbManager`)**：实现对 USB 总线状态的动态感知与指数退避重连机制（Backoff Reconnect）。
* **休眠唤醒（Suspend / Resume）自愈**：彻底解决原项目在笔记本合盖睡眠唤醒（S3/S0ix）后 USB 重置导致驱动假死的通病。遇到总线断线（`rusb::Error::NoDevice`）时自动失效旧会话，当下一次验证请求到达时自动扫描总线重新协商 TLS-PSK 硬件隧道。
* **容错启动**：若系统开机时硬件尚未完成总线枚举，D-Bus 接口照常注册就绪，首个业务请求到来时自动按需连接硬件，消除开机竞态启动失败。

#### 🎯 生物识别引擎与录入防抖安全防线
* **纯 Rust 图像识别管线**：彻底剥离上 GB 的臃肿 OpenCV 依赖（SIFT、BFMatcher、RANSAC）。放弃在微型低分辨率传感器上极易失效的单应性大图拼合，改用稳健的多模板（每指最多 5 个独立模板）策略。
* **双层误识率（FAR）安全边界加固**：将基准判定阈值校准提升至 `0.38`；引入二级置信度防线（单模板 `>= 0.44` 高置信直通，`[0.38 .. 0.44)` 边缘区间强制要求至少有两个模板给出正向相关度，且要求至少 28 个有效纹线结构块），大幅降低误认他人手指风险。
* **录入防抖与物理离开检测**：
  * 实现 `EnrollStageResult::DuplicatePress`（>0.95 相似度）防抖拦截，提示用户微调移动手指，确保多模板覆盖不同的指腹与边缘区域；
  * 新增 `poll_finger_up` 硬件事件检测，录入成功后强制轮询等待手指抬起，防止同一次按压连发。

#### 🔐 密码学与系统安全加固
* **权限掩码取反漏洞修复**：彻底修复原 C++ 版本中 `umask(0600)` 导致的生成文件为 `0066`（全局可读写）的严重漏洞，强制统一实施 `0077` umask 以及显式 `0700`/`0600` POSIX 权限位。
* **PolicyKit 异步鉴权网关**：对敏感 D-Bus 接口（`EnrollStart`、`DeleteEnrolledFingers`、`DeleteEnrolledFinger`）强制接入 Polkit 鉴权（`net.reactivated.fprint.device.*`），严防普通本地用户未提权录入或篡改管理员指纹。
* **硬件锚定 AEAD 存储**：模板采用基于硬件 TLS-PSK 派生的密钥结合 ChaCha20-Poly1305 加密落盘（`/var/lib/fprint/*.bin`）。所有写入均采用临时文件 + `sync_all` + 原子替换 rename，掉电绝不损坏数据。

#### 📦 多发行版打包与一键交付
* **一键交钥匙式脚本**：
  * `scripts/install.sh`：自动完成编译、systemd 服务注册、D-Bus 激活、屏蔽原生冲突 fprintd、配置 Ubuntu/Debian PAM 等全流程；
  * `scripts/uninstall.sh`：一键干净卸载、注销服务、恢复解封原生 fprintd，并支持 `--purge` 深度清理。
* **全生态打包规范**：
  * Debian / Ubuntu：原生 `.deb` 打包脚本（`scripts/package-deb.sh`）；
  * RedHat / Fedora / openSUSE：原生 `.rpm` spec 与打包脚本（`packaging/rpm/fingerprint-fpc.spec`，`scripts/package-rpm.sh`）；
  * Arch Linux：原生 `PKGBUILD` 与包安装脚本（`packaging/arch/PKGBUILD`）；
  * 通用 Linux：便携独立绿色归档包（`.tar.gz`，`scripts/package-tar.sh`）；
  * 聚合脚本：全格式一键流水线脚本 `scripts/package-all.sh`。
