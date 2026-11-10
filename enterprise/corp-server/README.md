# magpie-corp-server

企业内部的控制面参考实现：给 [`../corp-plugin`](../corp-plugin) 用的那五个接口，
以及**最重要的一段**——设备 enroll 时，在网关建一条 caller key，把它的值当作
`deviceToken` 交给设备。

接口契约见 [`../../devtools/corp-plugin-protocol.md`](../../devtools/corp-plugin-protocol.md)。
这份实现是照着契约写的，读它可以当规格来读。

## 为什么 deviceToken 是网关 Key

```
员工 enroll
  → 本服务向 IdP 换 id_token、校验
  → 本服务调网关管理 API：给这个人建一条 caller key（限定模型与额度）
  → 把 key 的值作为 deviceToken 返回
  → 插件把它写进 provider 的 apiKey

之后：Agent → 本地 magpie → 企业网关（网关自己校验这条 key、自己计量）→ 厂商
```

好处是**模型流量根本不经过本服务**，也不需要维护第二套令牌体系。代价是：
设备重复 enroll 必须撤掉旧 Key，否则一份凭据能复制到多台机器。

## 跑起来

先有一个带管理 API 的网关：

```bash
MAGPIE_ADMIN_ADDR=0.0.0.0:3450 MAGPIE_ADMIN_TOKEN=<32位随机> magpie serve
```

再起本服务：

```bash
cd enterprise/corp-server
export CORP_PORT=3600
export CORP_GATEWAY_ADMIN_URL=http://127.0.0.1:3450
export CORP_GATEWAY_ADMIN_TOKEN=<同一个 token>
export CORP_GATEWAY_PUBLIC_URL=https://ai.corp.example/v1
export CORP_PUBLIC_URL=https://control.corp.example
# 真实部署必填，缺了 enroll 会失败关闭
export CORP_OIDC_ISSUER=https://sso.corp.example
export CORP_OIDC_AUTHORIZE=https://sso.corp.example/oauth2/authorize
export CORP_OIDC_CLIENT_ID=magpie-corp
export CORP_OIDC_CLIENT_SECRET=<IdP 客户端密钥>
node src/server.mjs
```

### 本机演示（无 IdP）

```bash
CORP_ALLOW_DEMO_SIGNIN=true node src/server.mjs
```

打开后 enroll 时用 `demo:someone@corp.example` 当授权码，服务端不校验 IdP，直接用这个邮箱
建 Key。**只要配了 `CORP_OIDC_CLIENT_SECRET`，这个开关就自动失效**——不能在生产上被误开。

## 配置

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `CORP_PORT` | 3600 | 监听端口（只绑 `127.0.0.1`） |
| `CORP_PUBLIC_URL` | `http://127.0.0.1:<port>` | 员工机访问本服务的外部地址 |
| `CORP_GATEWAY_ADMIN_URL` | `http://127.0.0.1:3501` | 网关管理 API |
| `CORP_GATEWAY_ADMIN_TOKEN` | 空 | 网关管理 token，**空时 enroll 失败关闭** |
| `CORP_GATEWAY_PUBLIC_URL` | `http://127.0.0.1:3499/v1` | 下发到员工机的网关地址 |
| `CORP_OIDC_*` | 示例值 | issuer / authorize / client id / client secret |
| `CORP_ALLOW_DEMO_SIGNIN` | false | 仅演示；配了 client secret 即失效 |
| `CORP_NAME` | 示例公司 | 下发给插件显示的公司名 |
| `CORP_PLAN_MODELS` | `*` | 每人 Key 的模型白名单，逗号分隔 |
| `CORP_PLAN_LIMIT` | 空 | 每人 Key 的额度，如 `{"period":"month","cost":40}` |
| `CORP_DEVICE_TOKEN_DAYS` | 90 | 设备 Key 有效期 |
| `CORP_STATE_FILE` | `src/state.json` | 设备、用量、脱敏记录 |

## 接口

| 接口 | 认证 | 说明 |
| --- | --- | --- |
| `GET /api/v1/corp/config` | 无 | 发布 OIDC 参数与网关地址，插件据此自动发现 |
| `POST /api/v1/device/enroll` | 无（凭授权码） | 换 id_token → 建网关 Key → 发 deviceToken |
| `GET /api/v1/client/bundle` | deviceToken | 供应商/指令/MCP/技能，支持 `If-None-Match` → 304 |
| `POST /api/v1/telemetry/usage` | deviceToken | 用量行，`rowId` 去重 |
| `POST /api/v1/telemetry/masking` | deviceToken | 脱敏命中，只有类型与占位符 |
| `GET /__admin/summary` | 无（仅回环） | 演示用的汇总视图 |

## 安全边界

- **只监听 `127.0.0.1`**：真正部署时前面要有反向代理做 TLS。
- **失败关闭**：没有网关管理 token 就不发 Key，不降级成"假令牌"。
- **只存 value 的 SHA-256**：重启后能按哈希找到并撤销 Key，但打不出第二次。
- **白名单落库**：`sanitizeUsage` / `sanitizeMasking` 只留协议里点名的字段。客户端多发的
  提示词、厂商账号、Cookie 一律丢弃（有测试）。
- **重复 enroll 撤旧 Key**：旧设备的 token 变成"未知令牌"，不是"已撤销设备"——
  后者只留给管理员手工停用的设备。

## 测试

```bash
# 验签：不需要任何外部服务，16 个用例
node test/oidc.test.mjs

# 接口：只用本机服务，不碰网关（2 个契约用例通过，7 个 enroll 用例跳过）
node test/server.test.mjs

# 接上真实网关，9 个全跑
CORP_BASE=http://127.0.0.1:3600 \
CORP_GATEWAY_ADMIN_TOKEN=<token> \
node test/server.test.mjs
```

## 明确没做的

- **设备绑定**：`publicKeyPem` 收了但没用，令牌可被复制到别的机器（除非你另做绑定）。
- **刷新令牌**：设备令牌到期要重新登录，没有静默续期。
- **状态是一个 JSON 文件**：够演示和试点，不够并发多副本。生产需要真正的数据库。
- **用量只落库**：没做对账、计费、限额告警。
- **只验证 RSA 与 ECDSA**：`RS256/384/512`、`ES256/384/512`。`HS*` 和 `EdDSA` 被拒绝而不是
  猜测处理——IdP 只给这两种的话，要在这里加一个分支，不是把校验放宽。

## id_token 验签

[`src/oidc.mjs`](src/oidc.mjs) 做这些事，任何一条不过就拒绝登录：

| 检查 | 不过时的错误码 |
| --- | --- |
| 三段结构、header/payload 是 JSON | `id_token_malformed` |
| 算法在白名单里（拒绝 `none` 与 `HS*`） | `id_token_alg_unsupported` |
| `kid` 在 IdP 发布的 JWKS 里 | `id_token_key_unknown` |
| 密钥类型与算法匹配（RSA/EC，曲线也对） | `id_token_key_mismatch` |
| **签名与公钥相符** | `id_token_signature` |
| `iss` 是本 IdP | `id_token_issuer` |
| `aud` 含本服务 `client_id` | `id_token_audience` |
| `azp`（若有）是本服务 | `id_token_authorized_party` |
| `exp` 未过期（容忍 `CORP_OIDC_CLOCK_TOLERANCE_SECONDS`） | `id_token_expired` |
| `iat`/`nbf` 不在未来 | `id_token_not_yet` |
| `nonce` 与本次登录一致 | `id_token_nonce` |

JWKS 缓存在进程内（1 小时），一个没见过的 `kid` 会强制再拉一次，应对 IdP 轮换密钥。
`test/oidc.test.mjs` 用测试自己生成的 RSA 和 EC 密钥，逐一验证上述每一条都被拒绝——
包括「改掉 payload 里的 email 冒充管理员」和「`alg: none` 的裸签名」。
