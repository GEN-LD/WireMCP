# WireMCP HTTP 调用技能文档

> 面向大模型 Agent 的 WireMCP HTTP 模式调用指南

## 1. 概述

WireMCP 是一个基于 MCP（Model Context Protocol）协议的网络流量分析服务，底层依赖 tshark（Wireshark 命令行工具）和 URLhaus 威胁情报。通过 HTTP 模式，大模型 Agent 可以远程调用 WireMCP 的全部网络分析能力。

### 1.1 核心能力

| 能力域 | 说明 |
|---|---|
| 实时抓包 | 捕获指定网络接口的实时流量 |
| PCAP 离线分析 | 对已有 PCAP 文件进行协议统计、会话分析、数据包解析 |
| 传输层问题诊断 | 检测 TCP 层的 SYN 丢包、RST 异常、重传、零窗口等问题 |
| 应用层问题诊断 | 检测 HTTP 4xx/5xx 错误、重定向循环、响应超时、DNS 失败等 |
| TLS 解密分析 | 利用 SSLKEYLOGFILE 解密 TLS 流量，检测弱版本/弱密码，分析明文 HTTP 内容 |
| 凭据提取 | 从 PCAP 中提取 HTTP Basic Auth、FTP、Telnet 明文凭据及 Kerberos 哈希 |
| 威胁情报 | 实时抓包或指定 IP 与 URLhaus 黑名单比对 |
| 自定义 tshark 命令 | 当内置工具不满足需求时，执行任意 tshark 过滤/提取命令 |

### 1.2 适用场景

- **网络故障排查**：应用访问慢、连接超时、间歇性断连
- **安全分析**：凭据泄露检测、恶意 IP 识别、TLS 弱配置审计
- **流量取证**：PCAP 文件离线分析、协议分布统计、会话还原
- **CTF / 安全竞赛**：流量包分析、flag 提取、隐藏通信检测
- **运维监控**：实时抓包 + 威胁情报联动

---

## 2. HTTP 接口规范

### 2.1 启动服务

```bash
node index.js --http [--port <端口号>]
```

- 默认端口：`10001`
- 端点：`http://localhost:10001/mcp`

### 2.2 协议格式

WireMCP HTTP 模式遵循 **MCP Streamable HTTP Transport** 规范，底层为 **JSON-RPC 2.0**。

- **请求方法**：`POST`
- **Content-Type**：`application/json`
- **响应格式**：
  - 简单响应 → 直接返回 JSON
  - 流式响应 → 返回 `text/event-stream`（SSE）

### 2.3 会话管理

WireMCP 使用有状态会话模式（stateful）：

1. 客户端发送 `initialize` 请求
2. 服务端在响应头中返回 `Mcp-Session-Id`
3. 后续所有请求必须携带 `Mcp-Session-Id` 请求头
4. 客户端发送 `DELETE` 请求终止会话

**注意**：当前版本仅支持单会话，同一时刻只有一个客户端可以连接。

---

## 3. 调用流程

### 3.1 完整交互序列

```
Step 1: initialize    → 建立会话，获取 sessionId
Step 2: tools/list    → 获取工具清单（name + description + inputSchema）
Step 3: tools/call    → 调用具体工具
Step 4: (可选) 重复 Step 3
Step 5: DELETE /mcp   → 终止会话
```

### 3.2 Step 1 — 初始化

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-03-26",
      "capabilities": {},
      "clientInfo": {
        "name": "my-agent",
        "version": "1.0.0"
      }
    }
  }'
```

**响应示例**：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2025-03-26",
    "capabilities": {
      "tools": { "listChanged": true }
    },
    "serverInfo": {
      "name": "wiremcp",
      "version": "1.0.0"
    }
  }
}
```

**记录响应头中的 `Mcp-Session-Id`，后续请求必须携带。** 可以用 `-i` 参数查看响应头：

```bash
curl -i -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"my-agent","version":"1.0.0"}}}'
# 响应头中包含: Mcp-Session-Id: <sessionId>
```

### 3.3 Step 2 — 获取工具列表

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list"
  }'
```

**响应示例**：

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "capture_packets",
        "description": "Capture live traffic and provide raw packet data as JSON for LLM analysis",
        "inputSchema": {
          "type": "object",
          "properties": {
            "interface": { "type": "string", "default": "en0", "description": "Network interface to capture from (e.g., eth0, en0)" },
            "duration": { "type": "number", "default": 5, "description": "Capture duration in seconds" }
          }
        }
      }
    ]
  }
}
```

返回的 `tools` 数组中每个元素包含：
- `name`：工具名称，调用时使用
- `description`：功能描述，Agent 据此判断何时调用
- `inputSchema`：参数的 JSON Schema，定义每个参数的类型、是否必填、默认值、描述

### 3.4 Step 3 — 调用工具（通用格式）

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "<工具名>",
      "arguments": {
        "<参数名>": "<参数值>"
      }
    }
  }'
```

**成功响应**：

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "<分析结果文本>"
      }
    ]
  }
}
```

**错误响应**（包含 `isError: true`）：

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [{ "type": "text", "text": "Error: tshark not found" }],
    "isError": true
  }
}
```

### 3.5 Step 5 — 终止会话

```bash
curl -X DELETE http://localhost:10001/mcp \
  -H "Mcp-Session-Id: <sessionId>"
```

---

## 4. 工具详解

### 4.1 capture_packets — 实时抓包

| 属性 | 值 |
|---|---|
| 名称 | `capture_packets` |
| 功能 | 在指定网络接口上捕获实时流量，返回结构化 JSON 数据包列表 |
| 调用时机 | 需要观察当前网络实时流量时；无 PCAP 文件、需现场取证时 |

**参数**：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `interface` | string | 否 | `"en0"` | 网络接口名（如 `eth0`、`en0`、`Wi-Fi`） |
| `duration` | number | 否 | `5` | 捕获时长，1~60 秒整数 |

**调用示例**：

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "capture_packets",
      "arguments": {
        "interface": "eth0",
        "duration": 10
      }
    }
  }'
```

**返回内容**：JSON 格式的数据包数组，包含帧号、源/目的 IP、源/目的端口、TCP 标志、时间戳、HTTP 方法/状态码等字段。输出超过 720KB 时自动截断。

---

### 4.2 analyze_pcap — PCAP 通用分析

| 属性 | 值 |
|---|---|
| 名称 | `analyze_pcap` |
| 功能 | 解析 PCAP 文件，提取唯一 IP 列表、URL 列表、协议列表及完整数据包 JSON |
| 调用时机 | 拿到一个 PCAP 文件，需要快速了解整体概况时；作为分析的第一步 |

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `pcapPath` | string | 是 | PCAP 文件路径（支持 `.pcap` `.pcapng` `.cap`） |

**调用示例**：

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "analyze_pcap",
      "arguments": {
        "pcapPath": "./capture.pcap"
      }
    }
  }'
```

**返回内容**：唯一 IP 列表、URL 列表、协议列表、数据包 JSON 数据及截断信息。输出超过 200KB 时自动截断。

---

### 4.3 get_summary_stats — 协议层次统计

| 属性 | 值 |
|---|---|
| 名称 | `get_summary_stats` |
| 功能 | 分析 PCAP 文件的协议层次分布（各协议占比、数据量、抓包数） |
| 调用时机 | 需要了解流量中各协议占比时；判断 PCAP 中主要是什么协议流量 |

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `pcapPath` | string | 是 | PCAP 文件路径 |

**调用示例**：

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "tools/call",
    "params": {
      "name": "get_summary_stats",
      "arguments": {
        "pcapPath": "./capture.pcap"
      }
    }
  }'
```

**返回内容**：tshark 协议层次树，展示各协议层的数据包数、字节数、占比。

---

### 4.4 get_conversations — TCP 会话统计

| 属性 | 值 |
|---|---|
| 名称 | `get_conversations` |
| 功能 | 提取 PCAP 文件中所有 TCP 会话的统计信息（地址对、端口、收发字节数、持续时间） |
| 调用时机 | 需要了解哪些 IP 对之间有通信、流量大小分布时；排查哪些连接数据量异常 |

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `pcapPath` | string | 是 | PCAP 文件路径 |

**调用示例**：

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 6,
    "method": "tools/call",
    "params": {
      "name": "get_conversations",
      "arguments": {
        "pcapPath": "./capture.pcap"
      }
    }
  }'
```

**返回内容**：TCP 会话统计表，包含正向/反向字节数、帧数、持续时间。输出超过 100KB 时自动截断。

---

### 4.5 extract_credentials — 凭据提取

| 属性 | 值 |
|---|---|
| 名称 | `extract_credentials` |
| 功能 | 从 PCAP 文件中提取 HTTP Basic Auth、FTP、Telnet 明文凭据及 Kerberos 哈希 |
| 调用时机 | 安全审计场景，检测是否存在明文传输的密码；CTF 中提取隐藏凭据 |

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `pcapPath` | string | 是 | PCAP 文件路径 |

**调用示例**：

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 7,
    "method": "tools/call",
    "params": {
      "name": "extract_credentials",
      "arguments": {
        "pcapPath": "./capture.pcap"
      }
    }
  }'
```

**返回内容**：
- **Plaintext Credentials**：类型（HTTP Basic Auth / FTP / Telnet）、用户名、密码、帧号
- **Encrypted Credentials**：Kerberos 哈希值、用户名、Realm、hashcat 破解命令

---

### 4.6 analyze_l4_network — 传输层问题诊断

| 属性 | 值 |
|---|---|
| 名称 | `analyze_l4_network` |
| 功能 | 分析 PCAP 文件中 TCP 层网络问题：SYN 无响应、RST 拒绝、SYN 重传、SYN Flood、超时重传、零窗口、异常 RST、挥手不完整 |
| 调用时机 | 用户反馈"连不上""超时""断连"等连接层问题；需要诊断 TCP 握手/挥手异常时 |

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `pcapPath` | string | 是 | PCAP 文件路径 |
| `tsharkArgs` | string | 是 | tshark 过滤参数，用于缩小分析范围。如 `-Y "ip.addr == 10.0.0.1"` 或 `-Y "http"` |

**调用示例**：

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 8,
    "method": "tools/call",
    "params": {
      "name": "analyze_l4_network",
      "arguments": {
        "pcapPath": "./capture.pcap",
        "tsharkArgs": "-Y \"ip.addr == 192.168.1.100\""
      }
    }
  }'
```

**返回内容**：JSON 格式报告，包含每个 TCP 流的问题列表、问题类型、详细描述。

---

### 4.7 analyze_l7_network — 应用层问题诊断

| 属性 | 值 |
|---|---|
| 名称 | `analyze_l7_network` |
| 功能 | 分析 PCAP 文件中应用层问题：HTTP 4xx/5xx 错误、重定向循环、响应极慢、Content-Length 不匹配、服务端提前 FIN、DNS 查询失败、DNS 解析超时 |
| 调用时机 | 用户反馈"页面报错""访问慢""重定向死循环""DNS 无法解析"等应用层问题 |

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `pcapPath` | string | 是 | PCAP 文件路径 |
| `tsharkArgs` | string | 是 | tshark 过滤参数，如 `-Y "http"` 或 `-Y "ip.addr == 10.0.0.1"` |

**调用示例**：

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 9,
    "method": "tools/call",
    "params": {
      "name": "analyze_l7_network",
      "arguments": {
        "pcapPath": "./capture.pcap",
        "tsharkArgs": "-Y \"http\""
      }
    }
  }'
```

**返回内容**：JSON 格式报告，包含每个流/事务的应用层问题列表。

---

### 4.8 analyze_ssl_tls — TLS 解密分析

| 属性 | 值 |
|---|---|
| 名称 | `analyze_ssl_tls` |
| 功能 | 解密 SSL/TLS 流量：分析 TLS 握手安全信息（弱版本、弱密码套件），利用 SSLKEYLOGFILE 解密流量，提取 HTTP 明文内容，检测 HTTP 问题 |
| 调用时机 | 需要查看 HTTPS 加密流量的明文内容时；审计 TLS 配置安全性时；排查 HTTPS 服务异常时 |

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `pcapPath` | string | 是 | PCAP 文件路径 |
| `sslKeylogPath` | string | 是 | SSLKEYLOGFILE 文件路径（NSS Key Log 格式，通常为 `.txt` 或 `.log`） |

**调用示例**：

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 10,
    "method": "tools/call",
    "params": {
      "name": "analyze_ssl_tls",
      "arguments": {
        "pcapPath": "./capture.pcap",
        "sslKeylogPath": "./sslkeylog.txt"
      }
    }
  }'
```

**返回内容**：JSON 格式报告，包含：
- TLS 安全问题列表（弱版本如 TLS 1.0、弱密码套件如 RC4/MD5）
- 解密后的 HTTP 请求/响应摘要
- HTTP 问题检测结果（4xx/5xx、重定向循环、响应过慢等）

---

### 4.9 check_threats — 实时抓包 + 威胁情报

| 属性 | 值 |
|---|---|
| 名称 | `check_threats` |
| 功能 | 实时抓包提取 IP 地址，与 URLhaus 黑名单比对，识别恶意 IP |
| 调用时机 | 需要检查当前网络中是否存在与恶意服务器通信的行为；实时威胁监控 |

**参数**：

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `interface` | string | 否 | `"en0"` | 网络接口名 |
| `duration` | number | 否 | `5` | 捕获时长（1~60 秒） |

**调用示例**：

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 11,
    "method": "tools/call",
    "params": {
      "name": "check_threats",
      "arguments": {
        "interface": "eth0",
        "duration": 15
      }
    }
  }'
```

**返回内容**：捕获到的所有 IP 列表 + URLhaus 黑名单匹配结果。

---

### 4.10 check_ip_threats — 单 IP 威胁查询

| 属性 | 值 |
|---|---|
| 名称 | `check_ip_threats` |
| 功能 | 查询指定 IP 是否在 URLhaus 黑名单中 |
| 调用时机 | 已知可疑 IP，需要快速验证是否为恶意地址；从其他分析工具的输出中获取到 IP 后做二次确认 |

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `ip` | string | 是 | IPv4 地址（如 `192.168.1.1`），需符合正则 `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` |

**调用示例**：

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 12,
    "method": "tools/call",
    "params": {
      "name": "check_ip_threats",
      "arguments": {
        "ip": "185.220.101.45"
      }
    }
  }'
```

**返回内容**：IP 地址 + 是否在 URLhaus 黑名单中。

---

### 4.11 exec_tshark — 自定义 tshark 命令

| 属性 | 值 |
|---|---|
| 名称 | `exec_tshark` |
| 功能 | 对 PCAP 文件执行自定义 tshark 命令，提供其他工具无法覆盖的高级分析能力 |
| 调用时机 | 内置工具无法满足特定需求时（如特定字段提取、复杂过滤、自定义统计）；**作为最后手段，优先使用内置工具** |

**参数**：

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `pcapPath` | string | 是 | PCAP 文件路径 |
| `tsharkArgs` | string | 是 | tshark 参数字符串，如 `"-T fields -e http.host -Y \"http.request\""` |

**常用 tsharkArgs 示例**：

| 目的 | tsharkArgs 值 |
|---|---|
| 提取 HTTP 响应体 | `-T fields -e http.file_data -Y "http.response"` |
| 提取 HTTP 请求头 | `-T fields -e http.request.method -e http.host -e http.user_agent -e http.request.uri` |
| 按协议过滤 | `-Y "dns"` 或 `-Y "ftp"` |
| 按内容匹配 | `-Y "http.request.uri contains \"flag\""` |
| 逻辑组合 | `-Y "ip.addr == 192.168.1.1 && (http.request.method == \"GET\" || http.request.method == \"POST\")"` |

**调用示例 — 提取 HTTP 响应体**：

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 13,
    "method": "tools/call",
    "params": {
      "name": "exec_tshark",
      "arguments": {
        "pcapPath": "./capture.pcap",
        "tsharkArgs": "-T fields -e http.file_data -Y \"http.response\""
      }
    }
  }'
```

**调用示例 — 按内容匹配搜索**：

```bash
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 14,
    "method": "tools/call",
    "params": {
      "name": "exec_tshark",
      "arguments": {
        "pcapPath": "./capture.pcap",
        "tsharkArgs": "-T fields -e http.host -e http.request.uri -Y \"http.request.uri contains \\\"flag\\\"\""
      }
    }
  }'
```

**注意事项**：
- `-r` 参数由服务端自动添加，不要在 `tsharkArgs` 中指定
- 包含空格或逻辑运算符（`&&`、`||`、`!`）的过滤值必须用引号包裹
- 提取 HTTP 内容时使用 `http.file_data`，不要用 `data-text-lines`（后者只返回摘要）
- 输出超过 200KB 时自动截断

---

## 5. 工具选择决策树

```
有 PCAP 文件吗？
├── 否 → 需要实时抓包？
│         ├── 是 → 需要威胁检测？
│         │       ├── 是 → check_threats（抓包 + URLhaus 比对）
│         │       └── 否 → capture_packets（纯抓包）
│         └── 否 → 已有可疑 IP？→ check_ip_threats
│
└── 是 → 第一步：analyze_pcap（快速概览）
          │
          ├── 需要协议占比？→ get_summary_stats
          ├── 需要会话统计？→ get_conversations
          ├── 需要凭据提取？→ extract_credentials
          │
          ├── 问题出在哪层？
          │   ├── 传输层（连不上/超时/断连）→ analyze_l4_network
          │   ├── 应用层（报错/慢/重定向）→ analyze_l7_network
          │   └── TLS 层（需解密/弱配置审计）→ analyze_ssl_tls
          │
          └── 以上都不满足？→ exec_tshark（自定义命令兜底）
```

---

## 6. 典型工作流示例

### 6.1 场景：排查"网站访问超时"

```bash
# 1. 初始化会话
curl -i -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"agent","version":"1.0"}}}'
# → 记录响应头中的 Mcp-Session-Id

# 2. 快速概览 PCAP
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"analyze_pcap","arguments":{"pcapPath":"./capture.pcap"}}}'

# 3. 诊断 TCP 层问题
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"analyze_l4_network","arguments":{"pcapPath":"./capture.pcap","tsharkArgs":"-Y \"tcp\""}}}'

# 4. 诊断 HTTP 层问题
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"analyze_l7_network","arguments":{"pcapPath":"./capture.pcap","tsharkArgs":"-Y \"http\""}}}'
```

### 6.2 场景：HTTPS 流量解密分析

```bash
# 1. 初始化会话（同上，略）

# 2. TLS 解密 + HTTP 明文分析
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"analyze_ssl_tls","arguments":{"pcapPath":"./capture.pcap","sslKeylogPath":"./sslkeylog.txt"}}}'

# 3. 对解密发现的问题做进一步应用层诊断
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"analyze_l7_network","arguments":{"pcapPath":"./capture.pcap","tsharkArgs":"-Y \"http\""}}}'
```

### 6.3 场景：CTF 流量取证

```bash
# 1. 初始化会话（同上，略）

# 2. 快速概览
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"analyze_pcap","arguments":{"pcapPath":"./ctf.pcap"}}}'

# 3. 提取凭据
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"extract_credentials","arguments":{"pcapPath":"./ctf.pcap"}}}'

# 4. 按关键字搜索隐藏内容
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"exec_tshark","arguments":{"pcapPath":"./ctf.pcap","tsharkArgs":"-T fields -e http.request.uri -Y \"http.request.uri contains \\\"flag\\\"\""}}}'
```

### 6.4 场景：实时威胁监控

```bash
# 1. 初始化会话（同上，略）

# 2. 抓包 15 秒 + URLhaus 比对
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check_threats","arguments":{"interface":"eth0","duration":15}}}'

# 3. 对命中 IP 做二次确认
curl -X POST http://localhost:10001/mcp \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <sessionId>" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_ip_threats","arguments":{"ip":"185.220.101.45"}}}'
```

---

## 7. 错误处理

| 错误信息 | 原因 | 解决方式 |
|---|---|---|
| `tshark not found` | 系统未安装 Wireshark/tshark | 安装 Wireshark 并确保 tshark 在 PATH 中 |
| `非法的文件路径` | 路径包含 `..` 或空字符 | 使用安全的绝对路径或相对路径 |
| `不支持的文件扩展名` | 非 `.pcap`/`.pcapng`/`.cap` 文件 | 确保文件格式正确 |
| `非法的网络接口名称` | 接口名包含特殊字符 | 使用合法接口名（仅字母/数字/下划线/连字符/点号） |
| `捕获时长必须是 1~60 之间的整数` | duration 参数越界 | 传入 1~60 的整数 |
| `Invalid Request: Server already initialized` | 多客户端并发 | 确保只有一个客户端连接（当前仅支持单会话） |

---

## 8. 前置依赖

- **Node.js** >= 18
- **Wireshark/tshark**：必须安装并在 PATH 中可访问
- **网络权限**：实时抓包工具（`capture_packets`、`check_threats`）需要 root/Administrator 权限运行 tshark
