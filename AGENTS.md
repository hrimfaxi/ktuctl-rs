## 项目简介

单二进制 Rust CLI (`ktuctl-rs`)，通过 Netlink Generic 协议控制 `tutuicmptunnel` Linux 内核模块。是 C 版用户态工具的 Rust 重写。直接与内核模块通信——大部分命令需要 root 权限且内核模块已加载。

## 常用命令

```
cargo build                    # debug 构建
cargo build --release          # release 构建
cargo test                     # 运行测试（CI 执行此命令）
cargo clippy                   # lint 检查
cargo fmt                      # 格式化
cargo fmt -- --check           # 检查格式
```

Makefile 提供了快捷方式（`make build`、`make release`、`make test`、`make fmt`、`make clippy`、`make check`），只是封装了 cargo 命令。

OpenWrt 交叉编译通过 `./openwrt-aarch64.sh` 和 `./openwrt-x86_64.sh` 完成——需要本地 OpenWrt SDK 工具链，路径硬编码在 `~/temp/` 下。

## 架构

单 crate，无 workspace。所有源码在 `src/` 目录：

- `main.rs` — 入口，CLI 分发（双路径：clap 子命令 + 传统位置参数解析）
- `cli.rs` — clap derive 结构体（`Cli`、`Commands` 枚举）
- `commands.rs` — 所有子命令实现（`cmd_*` 函数）
- `netlink.rs` — 原始 Netlink Generic socket 层（手动构建/解析数据包，未使用高级 genetlink crate）
- `config.rs` — 协议常量，与内核模块通过 zerocopy 共享的 `#[repr(C)]` 结构体
- `helper.rs` — IP 解析、UID↔用户名映射、全局标志（`lazy_static` + `RwLock`）
- `uid_map.rs` — 加载 `/etc/tutuicmptunnel/uids` 实现用户名↔UID 映射

## 关键约定

- `config.rs` 中的协议结构体使用 `#[repr(C)]` 并带有显式填充字段（`_pad0`、`_pad1` 等），必须与内核模块的 C 结构体字节级对齐。使用 `zerocopy::{FromBytes, IntoBytes, Immutable}`。**不要重排或删除填充字段**。
- 协议结构体中的多字节整数字段采用**大端序**（内核约定）。读写端口和 ICMP ID 字段时使用 `helper.rs` 中的 `htons()`/`ntohs()`。
- IPv4 地址以 IPv4 映射 IPv6 格式（`::ffff:x.x.x.x`）存储在 16 字节的 `In6Addr` 数组中。
- netlink 层使用 `unsafe` 指针转换进行原始字节操作和结构体解析——这是有意为之，避免引入完整的 netlink 协议库。
- 全局状态使用 `lazy_static!` + `RwLock` 包装。两个全局变量：`UID_MAP` 和 `GLOBAL_FLAGS`。
- 错误处理全部使用 `anyhow::Result`，无自定义错误类型。
- 各命令自行手动解析参数（非 clap derive），接收 `&[String]` 切片。

## 测试

CI 运行 `cargo build --verbose` 和 `cargo test --verbose`。除 Rust 工具链外无集成测试前置依赖——二进制与内核模块通信，CI 环境中不存在该模块，因此测试仅限单元测试。

## 运行须知

- 二进制需要 root 权限 + `tutuicmptunnel` 内核模块已加载才能正常工作。缺少任一条件所有 netlink 操作都会失败。
- UID 配置文件路径硬编码为 `/etc/tutuicmptunnel/uids`。
- `script` 子命令从文件或标准输入（`-`）读取命令，支持 `#` 注释和 `;` 分隔的多命令行。
- `reaper` 和 `tui` 命令是存根（已废弃/未实现）。
