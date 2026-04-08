# ktuctl-rs

Rust 版本的 tutuicmptunnel-kmod 内核模块控制器。

## 简介

本项目是
[tutuicmptunnel-kmod](https://github.com/hrimfaxi/tutuicmptunnel-kmod)
内核模块的用户态控制工具，
使用 Rust 重写，通过 Netlink Generic 协议与内核通信，实现隧道配置、会话管理、用户管理等功能。

## 功能特性

- **工作模式**：支持 Server/Client 模式切换
- **客户端管理**：添加/删除客户端连接配置（地址、端口、UID）
- **服务端管理**：添加/删除服务端用户（地址、端口、ICMP ID）
- **状态监控**：查看运行状态、会话表、统计信息
- **配置管理**：导出/导入配置脚本，支持批量执行
- **接口管理**：绑定/解绑网络接口

## 快速开始

### 构建

```bash
# 本地构建
make build

# 发布构建
make release

# OpenWrt 交叉编译 (aarch64)
./openwrt-aarch64.sh

# OpenWrt 交叉编译 (x86_64)
./openwrt-x86_64.sh
```

### 基本用法

```bash
# 查看状态
ktuctl-rs status

# 服务端模式
ktuctl-rs server max-age 60

# 添加服务端用户
ktuctl-rs server-add user alice addr 192.168.1.100 port 443 icmp-id 1234

# 客户端模式
ktuctl-rs client

# 添加客户端连接
ktuctl-rs client-add user bob addr 10.0.0.1 port 443

# 导出配置
ktuctl-rs dump > backup.txt

# 执行脚本
ktuctl-rs script backup.txt
```

## LICENSE

```
GPL-v2
```
