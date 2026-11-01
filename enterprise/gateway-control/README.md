# gateway-control 受控网关适配器

`gateway-control` 是管理服务与 Magpie 网关 Key 存储之间的最小特权适配器。
它不解析人类可读 CLI 文本，不直接读写 `caller-keys.json`，也不暴露任意命令执行能力。

当前实现对应 M2-C4-02，并已由 admin-service -> auth-service 的 C4-03c 管理链路自动调用。
它已完成代码和 Mock/故障测试，但尚未完成真实 Magpie 请求行为 E2E、Docker 构建或企业
生产验收。

## 调用链

```text
admin-service
  -> auth-service
  -> 独立服务令牌
  -> gateway-control
  -> magpie gateway-key describe <id> --json
  -> magpie gateway-key policy apply <id> --json
  -> 同一 caller-keys.json + 独立 describe 回读
```

适配器只允许两个动作：

```text
GET  /api/v1/gateway-keys/{id}
POST /api/v1/gateway-keys/{id}/policy
GET  /healthz
```

`/healthz` 不需要服务令牌，只返回服务名和版本，不访问 Key 存储。其余路由必须携带：

```http
Authorization: Bearer <GATEWAY_CONTROL_TOKEN>
```

`POST policy` 还要求 `Content-Type: application/json`。Key ID 只允许
`^[A-Za-z0-9_-]{1,64}$`，不接受路径、空格、分号或 shell 字符。

## 策略请求

```json
{
  "schemaVersion": 1,
  "expectedPolicyRevision": "sha256:<64 lowercase hex characters>",
  "models": [
    "deepseek/deepseek-chat"
  ],
  "limits": [
    {
      "period": "month",
      "tokens": 5000000,
      "cost": 10,
      "cacheReads": false
    }
  ]
}
```

`limits: []` 表示没有额度上限，但 `models` 必须至少包含一个稳定模型 ID。
适配器与 Magpie 都会再次校验 schema、模型格式、额度窗口、冲突版本和
64 KiB 输入上限，不能依赖管理台单方面校验。

成功写入后，适配器会独立执行一次 `describe`。只有回读中的模型、额度窗口和
`policyRevision` 与请求一致时才返回 `200 applied`。如果写入结果不确定、超时或
回读不一致，则返回 `502` 和 `state: pending`，管理服务不得把它显示为已生效。

固定错误码包括：

| HTTP | error.code | 含义 |
| --- | --- | --- |
| 401 | `unauthorized` | 服务令牌缺失或错误 |
| 404 | `gateway_key_not_found` | 网关 Key 不存在 |
| 409 | `gateway_policy_conflict` | `expectedPolicyRevision` 冲突 |
| 413 | `request_too_large` | 请求体超过 64 KiB |
| 415 | `invalid_content_type` | 写请求不是 JSON |
| 422 | `gateway_schema_unsupported` | schema 版本不支持 |
| 422 | `gateway_output_invalid` | 请求或 Magpie 输出不安全/不合法 |
| 502 | `gateway_policy_unknown` | 写入结果无法确认，必须对账 |
| 502 | `gateway_readback_failed` | 独立回读与请求不一致 |
| 503 | `gateway_storage_unavailable` | Key 存储不可用 |
| 504 | `gateway_timeout` | 子进程超过默认 10 秒 |

## 配置

| 环境变量 | 必填 | 说明 |
| --- | --- | --- |
| `GATEWAY_CONTROL_TOKEN` | 是 | 至少 32 字符的独立内部服务令牌，不能复用 OIDC/Cookie/issuer/admin 令牌 |
| `GATEWAY_CONTROL_MAGPIE` | 是 | Magpie 二进制的绝对路径 |
| `GATEWAY_CONTROL_CONFIG_HOME` | 是 | 网关数据根目录；实际文件为 `${GATEWAY_CONTROL_CONFIG_HOME}/magpie/caller-keys.json` |
| `GATEWAY_CONTROL_BIND` | 否 | 默认 `127.0.0.1`；容器内为 `0.0.0.0`，但不发布宿主机端口 |
| `GATEWAY_CONTROL_PORT` | 否 | 默认 `3446` |
| `GATEWAY_CONTROL_TIMEOUT_MS` | 否 | 默认 `10000`，允许 `500` 到 `30000` |

服务启动时会验证 Magpie 和配置目录是绝对路径且存在，并拒绝对外复用已知 Secret。
子进程使用固定 argv、`shell: false`、固定工作目录和最小环境变量；请求体与子进程输出
上限均为 64 KiB。

## 本地测试

```powershell
& 'D:\Environment\node-v26.12.1\node.exe' `
  --check enterprise\gateway-control\src\service.js
& 'D:\Environment\node-v26.12.1\node.exe' `
  --test enterprise\gateway-control\test\gateway-control.test.mjs
```

当前结果：`15 passed, 0 failed`。覆盖服务令牌、脱敏、固定 Key ID、64 KiB 限制、
schema/额度校验、原始 JSON 传递、独立回读、超时和存储错误后的保守 `pending`、
确定性失败立即返回、子进程超时终止、输出上限和配置拒绝复用 Secret。

## Docker Compose

```powershell
cd enterprise
Copy-Item .env.example .env
# 设置独立的 GATEWAY_CONTROL_TOKEN
docker compose --profile gateway-control up -d
```

`gateway-control` 在 Compose 中：

- 不发布宿主机端口，只通过内部网络访问；
- 与 gateway 共用 `magpie-data:/config`，不挂载 auth/admin/issuer 数据；
- 使用 UID/GID `65532`、只读根文件系统、`cap_drop: ALL`、
  `no-new-privileges`、只读根目录外的 `/tmp` tmpfs；
- 设置请求、Keep-Alive 和服务自身超时。

`--profile auth` 或 `--profile admin` 会自动启动本服务；单独调试时可用
`--profile gateway-control`。当前机器没有 Docker CLI，因此 **Dockerfile 构建、Compose
启动和健康检查尚未实际运行**。
真实企业环境还需验证共享卷文件锁、SELinux/AppArmor、公司反向代理、服务令牌轮换和
告警接入。

## 安全边界

- 适配器只投影安全字段：Key ID/名称/状态、模型 patterns、额度窗口、账户摘要和
  `policyRevision`。不返回 Gateway Key、masked key、token hash、账户 ID、设备令牌或 Secret。
- 日志只记录动作、Key ID、requestId、状态码、错误码和耗时，不记录请求体、子进程输出或令牌。
- `gateway-control` 的令牌不是管理员会话，也不是 Magpie issuer Key。生产环境应使用独立
  Secret Manager 条目并定期轮换；服务只允许部署在管理网或内部 Compose 网络。
- `GATEWAY_CONTROL_TOKEN` 目前是共享服务令牌，不是 mTLS。mTLS、SPIFFE 或工作负载身份
  属于后续生产加固项，不能在未实现前宣称完成。

## 尚未完成

以下事项必须继续保持为“未完成/未验收”：

- C4-03c 已由 admin-service -> auth-service 自动调用本适配器，并完成 issuance journal、
  apply/readback 后交付、失败补偿和启动恢复的 Mock/故障测试；C4-03d 已补管理页额度/模型
  写表单、完整证据链状态和员工只读状态门户，但仍缺页面 E2E、失败恢复入口、
  operation/audit 查询和人工对账。
- 未证明真实 Magpie 的多凭证更新、零额度/低额度实际拒绝和模型白名单行为，属于 C4-04。
- 部分成功汇总已进入 C4-03c 核心测试；人工对账仍未实现，真实网关下的策略继承和旧凭证迁移端到端证据也尚未完成。
- 未接入 mTLS、公司 CA、反向代理、Docker/Compose 实机和企业 IdP。

因此当前状态是“受控适配器代码已实现并通过 Mock/故障测试”，不是
“企业生产调额与模型授权已完成”。

C4-03b/c 的生产接入还必须遵守：

- `cost` 超过 4 位小数直接返回 `400 invalid_quota`，不得静默四舍五入。
- `group/<name>` 只由 admin-service 在控制面展开为稳定模型 ID；auth-service、本适配器和
  Magpie 都不接收 group 表达式。
- 本适配器只执行 apply 和独立 describe，不拥有模型目录、策略首次初始化、Key 签发或
  客户端交付顺序；模型目录属于已实现的 C4-03a，其余分别属于 C4-03b/c。
