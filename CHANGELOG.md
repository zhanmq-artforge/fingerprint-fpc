# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

[English](CHANGELOG.md) | [简体中文](CHANGELOG.zh-CN.md)

---

## [1.0.0] - 2026-11-04

### 🚀 Initial Production Release: Complete Rust Rewrite of `fingerprint-ocv`

#### ⚡ Architecture & Concurrency Model
* **Complete Memory-Safe Rust Rewrite**: Dropped the brittle C++17 codebase, custom `jinx` continuation engine, and raw `libdbus-1` bindings. Rebuilt from the ground up using **Tokio** and **zbus 5** adhering to the Google Open Source Rust Style Guide.
* **Worker Starvation Elimination**: Fully decoupled heavy image enhancement, 2-stage grid alignment (NCC), and structural similarity (MSSIM) computation from Tokio worker threads by offloading execution to `tokio::task::spawn_blocking`.
* **Lock-Free Instant Cancellation**: Replaced blocking mutex contention during task abortion with atomic `cancel_token` (`Arc<AtomicBool>`). Disarming sensor commands are dispatched asynchronously, eliminating D-Bus reply lag.
* **D-Bus On-Demand Activation & Idle Sleep**: Implemented `--idle-timeout` (default 30s) alongside `/usr/share/dbus-1/system-services/net.reactivated.Fprint.service`. The daemon automatically releases hardware and terminates during idle periods, launching within 50ms upon authentication requests.

#### 🛡️ High-Availability (HA) & Hardware Self-Healing
* **Dynamic Lifecycle Management (`FpcUsbManager`)**: Implemented dynamic connection monitoring, USB bus scanning, and exponential backoff reconnection.
* **Suspend / Resume Resilience**: Fixed critical hardware reset failures after laptop sleep/wake (S3/S0ix). The daemon intercepts USB disconnects (`rusb::Error::NoDevice`), marks sessions invalid, and automatically re-negotiates TLS-PSK tunnels upon subsequent user authentication.
* **Fault-Tolerant Startup**: The D-Bus interface now registers cleanly even if the sensor controller is not yet enumerated at boot, automatically connecting on first demand.

#### 🎯 Biometric Engine & Anti-Debounce
* **Pure Rust Matching Pipeline**: Completely eliminated the 1GB+ OpenCV dependency (SIFT, BFMatcher, RANSAC). Replaced brittle Homography stitching with a robust multi-template strategy (up to 5 verified scan templates per finger).
* **Two-Tier FAR / FRR Boundary Protection**: Calibrated the baseline MSSIM threshold to `0.38`. Added secondary multi-template correlation checks for marginal scores (`[0.38 .. 0.44)`) and enforced a minimum of 28 valid ridge blocks, drastically reducing False Acceptance Rate (FAR).
* **Anti-Debounce & Finger Release Detection**:
  * Implemented `EnrollStageResult::DuplicatePress` (>0.95 similarity) to prompt users to reposition fingers and guarantee diverse spatial coverage.
  * Added `poll_finger_up` hardware event detection to enforce lifting fingers between enrollment stages.

#### 🔐 Security & POSIX Hardening
* **Umask Inversion Fix**: Replaced the dangerous `umask(0600)` call from the upstream C++ code (which created `0066` world-writable databases) with strict `0077` umask and explicit `0700`/`0600` POSIX permission bits.
* **PolicyKit Authorization Gate**: Enforced asynchronous Polkit verification on sensitive D-Bus endpoints (`EnrollStart`, `DeleteEnrolledFingers`, `DeleteEnrolledFinger`) via `net.reactivated.fprint.device.*` actions, closing local privilege escalation vulnerabilities.
* **Hardware-Bound AEAD Storage**: Encrypted biometric templates on disk (`/var/lib/fprint/*.bin`) using ChaCha20-Poly1305 with keys derived from the hardware TLS-PSK. All write operations use temporary files, `sync_all`, and atomic replacement.

#### 📦 Distribution Packaging & Turnkey Delivery
* **One-Click Turnkey Automation**:
  * `scripts/install.sh`: Fully automates compilation, systemd service registration, D-Bus activation, stock fprintd masking, and Ubuntu/Debian PAM configuration.
  * `scripts/uninstall.sh`: Restores stock fprintd, cleans unit files, and provides optional `--purge` biometric data wiping.
* **Multi-Distribution Packaging**:
  * Debian / Ubuntu: Native `.deb` packaging via `scripts/package-deb.sh`.
  * RedHat / Fedora: Native `.rpm` spec and packaging via `packaging/rpm/fingerprint-fpc.spec` and `scripts/package-rpm.sh`.
  * Arch Linux: Native `PKGBUILD` and pacman install scripts via `packaging/arch/PKGBUILD`.
  * Generic: Self-contained portable tarballs (`.tar.gz`) via `scripts/package-tar.sh`.
  * Master: All-in-one packaging pipeline `scripts/package-all.sh`.
