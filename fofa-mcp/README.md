# fofa-mcp

FOFA 搜索引擎的 MCP (Model Context Protocol) 工具服务器，让 AI 助手能够直接调用 FOFA API 进行网络资产搜索。

## 功能

- **fofa_search** - FOFA 资产搜索，支持完整查询语法
- **fofa_export** - 导出搜索结果到文件（CSV/JSON），数据不进入上下文，避免 token 消耗
- **fofa_user_info** - 查询账户信息（仅官方 API）
- **fofa_stats** - 搜索结果统计聚合分析（仅官方 API）
- **fofa_host** - 查询指定主机的详细信息（仅官方 API）

> 使用自定义 API URL 时，仅注册 `fofa_search` 和 `fofa_export`，其余工具仅在官方 FOFA API 下可用。

### 双模式运行

- **stdio 模式**（默认）：`fofa-mcp` — 用于 Claude Code、Cursor 等本地客户端
- **HTTP 模式**：`fofa-mcp serve` — 用于 Claude.ai 网页端（Custom Connector），支持 OAuth 2.1 + PKCE

## 安装

### npx 直接运行（无需安装）

```bash
npx fofa-mcp
```

### 全局安装

```bash
npm install -g fofa-mcp
```

### Claude Code 一键安装

```bash
claude mcp add fofa-mcp -e FOFA_API_KEY=your-api-key -- npx fofa-mcp
```

指定自定义 API 地址：

```bash
claude mcp add fofa-mcp -e FOFA_API_KEY=your-api-key -e FOFA_BASE_URL=https://your-api.com -- npx fofa-mcp
```

免费账户没有 API 配额时，可直接复用网页请求：设置 `FOFA_WEB_TOKEN`（或 `FOFA_TOKEN`）。程序会按网页端 `/v1/search` 请求签名，每次最多返回 50 条；签名密钥默认从 `https://fofa.info/` 动态读取，也可用 `FOFA_WEB_PRIVATE_KEY` 指定 PEM 文件。

注册机自动导入：将 `FOFA_WEB_TOKEN_FILE` 指向注册机输出的
`fofa_authorizations.json`，MCP 每次搜索都会读取最新一条 Authorization，无需手工复制 token；注册机新增账号后无需重启 MCP：

```bash
FOFA_WEB_TOKEN_FILE=../accounts/fofa_authorizations.json npm start
```

## 配置

### 环境变量

| 变量 | 必填 | 说明 |
|------|------|------|
| `FOFA_API_KEY` | API 模式必填 | FOFA API Key（在 [个人中心](https://fofa.info/userInfo) 获取） |
| `FOFA_EMAIL` | 官方 API 必填 | FOFA 账户邮箱（网页 token 模式可留空） |
| `FOFA_WEB_TOKEN` / `FOFA_TOKEN` | 网页模式必填 | 网页请求 `Authorization` 值；设置后自动使用 `https://api.fofa.info/v1` |
| `FOFA_WEB_TOKEN_FILE` | 网页模式可选 | 注册机生成的 `fofa_authorizations.json`；优先使用文件中最新 token |
| `FOFA_WEB_PRIVATE_KEY` | 否 | 网页签名私钥 PEM 文件路径；不设置则从 FOFA 首页读取加密配置 |
| `FOFA_BASE_URL` | 否 | 自定义 API 地址；网页模式默认 `https://api.fofa.info/v1` |
| `FOFA_PLAN` | 否 | `free`（默认）或 `paid`；免费模式限制分页大小并拒绝 `full` |
| `FOFA_MAX_PAGE_SIZE` | 否 | 每页上限，默认免费用户 50、付费用户 10000 |
| `FOFA_ALLOW_FULL` | 否 | 是否允许 `full=true`，默认仅付费模式允许 |
| `FOFA_USER_ID` | 否 | stdio 模式的用户标识，HTTP/OAuth 模式由客户端 ID 隔离 |
| `FOFA_MAX_REQUESTS_PER_MINUTE` | 否 | HTTP 模式每用户请求上限，默认 60 |

### Claude Desktop

编辑配置文件：

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "fofa": {
      "command": "npx",
      "args": ["fofa-mcp"],
      "env": {
        "FOFA_API_KEY": "your-api-key",
        "FOFA_BASE_URL": "https://fofa.info"
      }
    }
  }
}
```

### Cursor

```json
{
  "mcpServers": {
    "fofa": {
      "command": "npx",
      "args": ["fofa-mcp"],
      "env": {
        "FOFA_API_KEY": "your-api-key"
      }
    }
  }
}
```

## 工具参数

### fofa_search

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `query` | string | 是 | FOFA 查询语句 |
| `fields` | string | 否 | 返回字段，逗号分隔，默认 `ip,port,protocol,host,domain,title,server` |
| `page` | integer | 否 | 页码，默认 1 |
| `size` | integer | 否 | 每页数量，默认 50（免费用户上限 50），最大 10000 |
| `full` | boolean | 否 | 是否搜索全部数据，默认 false（仅最近一年） |

### fofa_export

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `query` | string | 是 | FOFA 查询语句 |
| `output_file` | string | 是 | 输出文件路径，支持 `.csv` 和 `.json` |
| `fields` | string | 否 | 返回字段，默认 `ip,port,protocol,host,domain,title,server` |
| `page` | integer | 否 | 页码，默认 1 |
| `size` | integer | 否 | 每页数量，默认 50（免费用户上限 50），最大 10000 |
| `full` | boolean | 否 | 是否搜索全部数据，默认 false |

### fofa_stats（仅官方 API）

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `query` | string | 是 | FOFA 查询语句 |
| `fields` | string | 否 | 统计字段，如 `country,port,protocol` |

### fofa_host（仅官方 API）

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `host` | string | 是 | 目标 IP 或域名 |
| `detail` | boolean | 否 | 是否获取详细信息 |

## HTTP 模式（serve，多用户）

用于部署为远程 MCP 服务器，支持 Claude.ai 网页端通过 OAuth Custom Connector 接入。每个 OAuth 客户端拥有独立的 FOFA API 配置、用户标识和速率窗口；访问令牌采用签名后加密格式，不把 API Key 暴露在明文 JWT payload 中。

### 启动

```bash
SERVER_URL=https://your-domain.com fofa-mcp serve
```

### 环境变量

| 变量 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `SERVER_URL` | 否 | `http://localhost:3000` | 服务对外公开地址 |
| `JWE_SECRET` | 否 | 自动生成 | 32 字节 base64 编码密钥（加密 authorization code） |
| `JWS_SECRET` | 否 | 自动生成 | 32+ 字节 base64 编码密钥（签名 access token） |
| `LISTEN_ADDR` | 否 | `:3000` | 监听地址（如 `0.0.0.0:8080`） |
| `FOFA_DEFAULT_PLAN` | 否 | `free` | OAuth 用户默认计划；免费模式适配普通免费 API Key |
| `FOFA_MAX_REQUESTS_PER_MINUTE` | 否 | `60` | 每个 OAuth 用户独立限流 |

> 未设置 `JWE_SECRET`/`JWS_SECRET` 时自动随机生成，重启后旧 token 失效，客户端会自动重新 OAuth。如需重启后 token 持续有效，手动设置固定密钥。

### 工作原理

1. Claude.ai 发现 OAuth 元数据（`/.well-known/oauth-authorization-server`）
2. 用户在浏览器授权页面填写 FOFA API 配置（API Key 或网页端 access token）
3. 服务端将配置加密为 JWE code，再签发 JWS access token
4. Claude.ai 使用 token 调用 `/mcp` 端点，服务端从 token 解出配置代为请求
5. **完全无状态**：服务端不存储任何用户凭据

### Claude.ai 配置

在 Claude.ai 中添加 Custom Connector，填入你部署的服务器地址即可，OAuth 发现和认证流程自动完成。

## Cloudflare Worker 部署（无服务器）

`worker/` 目录包含适配 Cloudflare Worker 的独立版本，零成本无服务器部署。

### 快速部署

```bash
cd worker
npm install
wrangler deploy
```

部署完成后会输出 Worker 地址（如 `https://fofa-mcp.<你的子域名>.workers.dev`），访问该地址确认部署成功。

### 推荐配置（生产环境）

建议设置固定密钥和自定义域名，避免 Worker 冷启动后旧 token 失效导致用户需要重新授权：

```bash
# 生成并设置固定密钥（推荐）
wrangler secret put JWE_SECRET
# 输入值，例如: openssl rand -base64 32 生成

wrangler secret put JWS_SECRET
# 输入值，同上
```

如果你有自定义域名（如 `mcp.example.com`），在 Cloudflare Dashboard 中给 Worker 绑定域名后设置：

```bash
wrangler secret put SERVER_URL
# 输入值: https://mcp.example.com
```

### 环境变量

| 变量 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `SERVER_URL` | 否 | 自动从请求推断 | 自定义域名（如 `https://mcp.example.com`） |
| `JWE_SECRET` | 否 | 自动生成 | 32 字节 base64 密钥（加密 authorization code） |
| `JWS_SECRET` | 否 | 自动生成 | 32 字节 base64 密钥（签名 access token） |
| `FOFA_WEB_PRIVATE_KEY` | 网页 token 模式 | — | 网页端 RSA 私钥 PEM；用 `wrangler secret put FOFA_WEB_PRIVATE_KEY` 设置 |

> **不设置密钥时**：每次 Worker 冷启动自动随机生成，已签发的 token 将失效，用户需重新 OAuth 授权。适合测试使用。
>
> **设置固定密钥后**：Worker 重启/重新部署后 token 持续有效，用户无需重复授权。**生产环境推荐**。

### 免费用户与多用户行为

- 免费用户可使用自己的 FOFA 邮箱/API Key，或网页端 access token，不依赖 VIP 字段或共享账号。
- `fofa_search`/`fofa_export` 在请求发出前执行免费分页上限；`full=true` 返回明确的计划限制错误。
- OAuth 用户的 `client_id` 作为稳定隔离键；不同用户不会共享 API Key、计划配置或限流计数。
- Worker 版本同步携带上述用户配置并执行每用户限流。

### 特点

- **零配置部署**：`wrangler deploy` 一条命令即可运行
- **零成本**：Cloudflare Worker 免费额度每天 10 万次请求
- **全球边缘**：自动部署到全球节点，低延迟
- **无需服务器**：不需要 VPS 或云主机

## 许可证

MIT License
