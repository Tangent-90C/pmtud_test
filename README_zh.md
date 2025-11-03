# IPv6 MTU 发现工具

[English](README.md) | 中文

一个用于发现 IPv6 路径 MTU 和检测 TCP MSS 钳制的命令行工具。

## 功能特性

- 使用 ICMP6 探测进行 IPv6 路径 MTU 发现
- TCP MSS 钳制检测（客户端和服务器模式）
- 高效 MTU 发现的二分搜索算法
- 跨平台支持（Linux、macOS、Windows）
- 详细的进度报告和统计信息
- MSS 完整性验证和篡改检测
- 网络错误场景处理
- 并发操作支持

## 系统要求

- Go 1.19 或更高版本
- Root/管理员权限（用于原始套接字操作）
- IPv6 网络连接

## 安装

### 从源码构建

```bash
git clone <repository-url>
cd ipv6-mtu-discovery
make deps
make build
```

### 系统级安装

```bash
make install
```

## 使用方法

### MTU 发现

```bash
# 基本 MTU 发现
sudo ./ipv6-mtu-discovery -t 2400:3200::1

# 详细输出
sudo ./ipv6-mtu-discovery -t 2400:3200::1 -v

# 自定义超时时间
sudo ./ipv6-mtu-discovery -t 2400:3200::1 -T 10

# 指定 MTU 范围
sudo ./ipv6-mtu-discovery -t 2400:3200::1 --min-mtu 1280 --max-mtu 1500
```

### TCP MSS 检测

```bash
# 客户端模式 MSS 检测
sudo ./ipv6-mtu-discovery -t 2400:3200::1 -m tcp-client -p 80

# 服务器模式 MSS 检测
sudo ./ipv6-mtu-discovery -t :: -m tcp-server -p 8080

# MSS 完整性验证
sudo ./ipv6-mtu-discovery -t 2400:3200::1 -m mss-integrity -p 80 --control-port 8080 --test-mss 1460
```

## 命令行选项

### 基本选项
- `-t, --target`: 目标 IPv6 地址（必需）
- `-m, --mode`: 操作模式（mtu, tcp-client, tcp-server, mss-integrity）[默认: mtu]
- `-p, --port`: MSS 检测的 TCP 端口 [默认: 80]
- `-v, --verbose`: 启用详细输出
- `-T, --timeout`: 超时时间（秒）[默认: 5]

### MTU 发现选项
- `--min-mtu`: 最小 MTU 值 [默认: 68]
- `--max-mtu`: 最大 MTU 值 [默认: 1500]

### MSS 完整性验证选项
- `--control-port`: 控制连接端口
- `--test-mss`: 测试 MSS 值

### 日志选项
- `--log-level`: 日志级别（debug, info, warn, error）
- `--log-file`: 启用文件日志
- `--log-path`: 日志文件路径

## 操作模式详解

### 1. MTU 发现模式 (`mtu`)
使用 ICMP6 回显请求进行路径 MTU 发现：
- 采用二分搜索算法高效确定最大 MTU
- 处理 ICMP6 "Packet Too Big" 响应
- 提供详细的探测进度和统计信息

### 2. TCP 客户端 MSS 检测 (`tcp-client`)
作为 TCP 客户端检测 MSS 钳制：
- 连接到指定的服务器和端口
- 检测协商的 MSS 值
- 识别 MSS 钳制情况

### 3. TCP 服务器 MSS 检测 (`tcp-server`)
作为 TCP 服务器检测 MSS 钳制：
- 监听指定端口等待连接
- 捕获客户端的 MSS 值
- 分析 MSS 修改情况

### 4. MSS 完整性验证 (`mss-integrity`)
验证 MSS 值的完整性：
- 建立控制连接交换验证信息
- 检测 MSS 篡改和修改
- 提供详细的完整性分析报告

## 构建目标

```bash
make build      # 构建二进制文件
make test       # 运行测试
make clean      # 清理构建产物
make deps       # 下载依赖
make lint       # 代码格式化和检查
make install    # 安装到系统
```

## 测试

### 运行所有测试
```bash
make test
```

### 运行集成测试
```bash
# 运行所有测试（包括集成测试）
./test_integration.sh

# 仅运行单元测试
./test_integration.sh unit

# 仅运行集成测试
./test_integration.sh integration
```

## 架构设计

工具采用模块化设计，组织为多个包：

- `cmd/`: 主应用程序入口点
- `internal/app/`: 应用程序逻辑和状态管理
- `internal/cli/`: 命令行界面和参数解析
- `internal/probe/`: ICMP6 探测和数据包处理
- `internal/network/`: TCP 连接和 MSS 检测
- `internal/validator/`: IPv6 地址和权限验证
- `internal/algorithm/`: 二分搜索算法实现
- `internal/display/`: 结果格式化和显示
- `internal/config/`: 配置管理
- `internal/stats/`: 统计信息收集
- `internal/logging/`: 日志系统
- `internal/platform/`: 平台特定功能

## 使用示例

### 基本 MTU 发现
```bash
# 发现到 Google IPv6 DNS 的路径 MTU
sudo ./ipv6-mtu-discovery -t 2001:4860:4860::8888 -v

# 输出示例：
# Starting IPv6 Path MTU Discovery to 2001:4860:4860::8888
# Testing MTU 784... Success
# Testing MTU 1142... Success  
# Testing MTU 1321... Failed (Packet Too Big, reported MTU: 1280)
# Testing MTU 1280... Success
# 
# MTU Discovery Results:
# Final MTU: 1280 bytes
# Probe attempts: 4
# Success rate: 75%
```

### MSS 完整性验证
```bash
# 验证 MSS 是否被中间设备修改
sudo ./ipv6-mtu-discovery -t 2400:3200::1 -m mss-integrity \
  -p 80 --control-port 8080 --test-mss 1460 -v

# 输出示例：
# Starting MSS Integrity Verification
# Test MSS: 1460, Control Port: 8080
# Establishing control connection...
# Performing MSS integrity verification...
# 
# MSS Integrity Results:
# Client sent MSS: 1460
# Server received MSS: 1440
# MSS Modified: Yes
# Modification Delta: -20
# Tampering Detected: Yes (Medium severity)
```

## 错误处理

工具提供详细的错误信息和处理：

- **权限错误**: 提示需要 root/管理员权限
- **网络错误**: 处理超时、连接拒绝等网络问题
- **地址验证**: 验证 IPv6 地址格式和可达性
- **平台兼容性**: 检测平台支持的功能

## 性能特性

- **高效算法**: 使用二分搜索最小化探测次数
- **并发支持**: 支持多个并发操作
- **资源管理**: 自动清理网络资源
- **统计收集**: 详细的性能和成功率统计

## 配置文件

支持 YAML 配置文件进行高级配置：

```yaml
# config.yaml 示例
network:
  timeout_ms: 5000
  max_retries: 3
  
mtu_discovery:
  min_mtu: 68
  max_mtu: 1500
  probe_timeout_ms: 3000
  
mss_verification:
  session_timeout_ms: 10000
  handshake_timeout_ms: 5000
  
logging:
  level: "info"
  file_enabled: true
  file_path: "logs/ipv6-mtu-discovery.log"
```

## 故障排除

### 常见问题

1. **权限不足**
   ```bash
   # 错误: socket: operation not permitted
   # 解决: 使用 sudo 运行
   sudo ./ipv6-mtu-discovery -t ::1
   ```

2. **IPv6 不支持**
   ```bash
   # 检查 IPv6 支持
   ip -6 addr show
   # 启用 IPv6 loopback
   sudo sysctl net.ipv6.conf.lo.disable_ipv6=0
   ```

3. **防火墙阻止**
   ```bash
   # 临时允许 ICMP6
   sudo ip6tables -I INPUT -p ipv6-icmp -j ACCEPT
   ```

## 许可证

[许可证信息待添加]

## 贡献

欢迎贡献代码！请查看 [贡献指南](CONTRIBUTING.md)。

### 开发环境设置

1. 克隆仓库
2. 安装 Go 1.19+
3. 运行 `make deps` 安装依赖
4. 运行 `make test` 确保测试通过
5. 使用 `make lint` 检查代码质量

## 相关文档

- [集成测试文档](INTEGRATION_TESTS.md)
- [架构设计文档](docs/architecture.md)
- [API 文档](docs/api.md)

## 支持

如有问题或建议，请：
1. 查看 [FAQ](docs/faq.md)
2. 搜索现有 [Issues](../../issues)
3. 创建新的 Issue 描述问题

---

**注意**: 此工具需要原始套接字权限，请确保在受信任的环境中使用。