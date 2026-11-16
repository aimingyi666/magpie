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

演示登录也接受 `demo-admin:someone@corp.example`：这个账号会带上第一个
`CORP_ADMIN_GROUPS` 分组，因此是管理员。插件登录页的「演示登录（管理员）」用的就是它。
前缀只在演示分支里读取，配了 IdP 后同样失效。

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
| `CORP_ADMIN_GROUPS` | `corp-admins,magpie-admins,admins` | 这些 IdP 组的人算企业管理员 |
| `CORP_ADMIN_EMAILS` | 空 | 额外按邮箱指定管理员 |
| `CORP_DEMO_ADMIN` | false | 演示登录的账号也算管理员 |
| `CORP_ADMIN_TOKEN` | 空 | 设置后，`POST /__admin/*` 必须带 `Authorization: Bearer <token>` |
| `CORP_CURSOR_BRIDGE` | `off` | `on` 时按下面的人/组下发 `cursor-bridge` 插件 |
| `CORP_CURSOR_BRIDGE_USERS` | 空 | 下发对象的邮箱，逗号分隔；`*` 表示所有人 |
| `CORP_CURSOR_BRIDGE_GROUPS` | 空 | 下发对象的 IdP 组，逗号分隔 |
| `CORP_CURSOR_BRIDGE_MODEL` | 空 | 插件接入的模型；裸模型名按 `corp/<model>`，空则用 provider 的默认模型 |

### 按人下发 Cursor 桥接插件

`CORP_CURSOR_BRIDGE=on` 加上 `CORP_CURSOR_BRIDGE_USERS` / `CORP_CURSOR_BRIDGE_GROUPS`
（或 `*`）后，命中的设备在 `/api/v1/client/bundle` 里多一条
`plugins: [{ id: "cursor-bridge", model: "corp/…" }]`；插件装上并开启该 agent 后，Cursor 的
请求走本机 magpie，再由 `corp` provider 转到企业网关。

策略也可以运行时改，写进 `state.pluginPolicy`，优先于环境变量：

```bash
curl -X POST http://127.0.0.1:3600/__admin/plugins/cursor-bridge \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $CORP_ADMIN_TOKEN" \
  -d '{"enabled":true,"users":["alice@corp.example"],"groups":["研发"],"model":"deepseek-flash"}'
```

`enabled:false` 撤回策略。客户端随后会断开 Cursor 与网关的连接，但不会卸载插件。

**策略和 `revision`：** `plugins` 是按设备算的，但策略每次改动（启用、换人、换模型、撤回）
都会发布一个新 `revision`。否则设备拿着旧 revision 会收到 `304`，撤回永远到不了它手上。
剩下的 `304` 逻辑不变：设备自己的 revision 就是"我上次拿到的那份"，相同即未变。
插件客户端每次同步都会从磁盘上的 bundle 重新应用一遍，因此漏掉一次、或安装失败后重试，
都会在下一轮收敛。

## 分享供应商与人员密钥

管理员登录插件后，可以在「管理员」页把本机 magpie 的供应商分享出来。服务端有两种模式：

| 模式 | 发生什么 | 适用 |
| --- | --- | --- |
| `native` | 插件把供应商的端点、模型和 Key 发给本服务；本服务调用网关管理 API 建/改供应商，网关直接访问厂商 | 企业网关需要自己持有厂商 Key |
| `remote` | 不搬运 Key，只发布网关的模型列表；客户端把企业网关当作一台 Remote magpie | 网关本身就是一台已配置好的 magpie |
| `off` | 下发空供应商列表，并删除本服务上一次写进网关的供应商 | 停止共享 |

`native` 的 Key 只在请求体里经过一次；本服务的状态只记录 `keyCount` 和掩码，
**不保存 Key 的值**。写进网关的供应商 id 记在 `sharing.installed`，切换模式或再次分享时
只删除这些 id，管理员手工加到网关的供应商不会被碰。

### 员工共享自己的 WorkBuddy 账号

企业网关装好并加载 WorkBuddy 插件（`@magpie-community/opencode-workbuddy-auth`）后，
员工可以在 corp-plugin 的「概览」页点「共享 WorkBuddy」：

1. 本服务向网关管理 API 发一次 `plugin-signin`（`method: 0`，`concurrent: true`，所以
   多个人可以同时扫码）；
2. 插件给的登录页（腾讯/WorkBuddy 自己显示二维码）由员工的本机服务交给默认浏览器打开；
3. 员工扫码完成后，账号落在网关的插件里；本服务再读一次该供应商的模型
   （`POST /v1/magpie/admin/provider/models`），记进 `state.workbuddy.imported`。
4. 管理员在「管理员」页勾选要下发的模型（`GET/PUT /api/v1/admin/workbuddy`）。
   只有勾选的模型并入企业目录并发布新 `revision`；未勾选的只留在管理员视图。

员工的本机 magpie 里已经登录过 WorkBuddy 时，不必再扫一次：插件把那份登录（含
access / refresh）通过 `POST /api/v1/share/workbuddy/import` 交给本服务，本服务转发给
网关的 `POST /v1/magpie/admin/plugin-import`，由网关插件写成自己的账号。之后本机服务
退出本机那份登录，同一个 token 只有一处续期。导入成功后仍走第 3、4 步：读模型、
等管理员勾选。

约束：

- 共享记录只有 `id`、`signInId`、供应商、设备/用户、状态、登录页 URL、账号、模型与时间，
  **不保存任何 WorkBuddy token**——扫码流程里 token 由网关的插件宿主持有；本机导入时
  它只在一次请求里穿过本服务，不写 state、不回显、不写日志。
- 只有 `on !== false` 的模型会被导入：账号主人自己在编辑器里取消勾选的模型不会被全企业使用。
- 导入不等于下发：管理员勾选前，员工的共享不开任何模型。分享模式是 `native` / `remote`
  时勾选会立即发布新 `revision`；`off` 或未设置时只保存勾选，等管理员开启分享。
- 员工只能读自己设备发起的共享；别人的 share id 返回 404。
- 网关没装 WorkBuddy 插件时 `plugin-signin` 回 400，本服务转成 409
  `workbuddy_unavailable`，页面上提示联系管理员。

每个员工 enroll 时都会在网关建一条 caller key（设备令牌就是它的值）。管理员页可以直接
修改这条 Key：

- `models` 模型白名单（空数组 = 全部）；
- `readOnly` 只读；
- `off` 停用；
- `limit` 额度，支持 `day` / `week` / `month` / `hours` / `days`，以及 `tokens` /
  `cost` / `cacheReads`。

修改带上网关返回的 `expectedRevision`，冲突返回 409，不会被静默覆盖。

## 接口

| 接口 | 认证 | 说明 |
| --- | --- | --- |
| `GET /api/v1/corp/config` | 无 | 发布 OIDC 参数与网关地址，插件据此自动发现 |
| `POST /api/v1/device/enroll` | 无（凭授权码） | 换 id_token → 建网关 Key → 发 deviceToken |
| `GET /api/v1/client/bundle` | deviceToken | 供应商/指令/MCP/技能 + 该设备命中的插件；支持 `If-None-Match` → 304 |
| `POST /api/v1/telemetry/usage` | deviceToken | 用量行，`rowId` 去重 |
| `POST /api/v1/telemetry/masking` | deviceToken | 脱敏命中，只有类型与占位符 |
| `GET /api/v1/device/me` | deviceToken | 设备、用户、角色、网关、当前分享摘要与本设备的 WorkBuddy 共享 |
| `POST /api/v1/share/workbuddy/start` | deviceToken | `{provider:"workbuddy"\|"workbuddy-ai"}` → 登录页 URL 与 share id |
| `POST /api/v1/share/workbuddy/import` | deviceToken | `{provider, account, auth}`：导入本机 magpie 已有的登录，`removed` 表示本机已退出 |
| `GET /api/v1/share/workbuddy/{id}` | deviceToken | 轮询扫码登录；完成时导入模型 |
| `POST /api/v1/share/workbuddy/{id}/cancel` | deviceToken | 取消这次登录 |
| `GET /api/v1/admin/sharing` | 管理员 deviceToken | 当前分享模式、来源与模型目录 |
| `PUT /api/v1/admin/sharing` | 管理员 deviceToken | `{mode:"native"\|"remote"\|"off", providers?, models?}` |
| `GET /api/v1/admin/workbuddy` | 管理员 deviceToken | 员工共享进来的账号、模型，以及已勾选下发的模型 |
| `PUT /api/v1/admin/workbuddy` | 管理员 deviceToken | `{provider:"workbuddy"\|"workbuddy-ai", models:[…]}`；只接受该账号列出的模型 |
| `GET /api/v1/admin/people` | 管理员 deviceToken | 用户、设备与每条网关 Key 的掩码/模型/额度 |
| `PATCH /api/v1/admin/people/{deviceId}` | 管理员 deviceToken | 修改该设备网关 Key 的模型、只读、启停与额度 |
| `GET /__admin/summary` | 无（仅回环） | 演示用的汇总视图，含当前插件策略 |
| `GET /__admin/plugins` | 无（仅回环） | 当前插件策略，以及策略实际命中的邮箱 |
| `POST /__admin/plugins/cursor-bridge` | 可选 `CORP_ADMIN_TOKEN` | 运行时设置/撤回 Cursor 桥接策略 |

## 安全边界

- **只监听 `127.0.0.1`**：真正部署时前面要有反向代理做 TLS。
- **失败关闭**：没有网关管理 token 就不发 Key，不降级成"假令牌"。
- **只存 value 的 SHA-256**：重启后能按哈希找到并撤销 Key，但打不出第二次。
- **管理员路由单独判定**：成员或未知令牌访问 `/api/v1/admin/*` 返回 403
  `forbidden_admin`，不会退化成空管理员。
- **native 分享的厂商 Key 不落盘**：只在本服务 → 网关管理 API 的请求里出现一次；
  状态文件只留掩码和数量。
- **白名单落库**：`sanitizeUsage` / `sanitizeMasking` 只留协议里点名的字段。客户端多发的
  提示词、厂商账号、Cookie 一律丢弃（有测试）。
- **重复 enroll 撤旧 Key**：旧设备的 token 变成"未知令牌"，不是"已撤销设备"——
  后者只留给管理员手工停用的设备。
- **插件只能选 id**：客户端只认自己的白名单（目前 `cursor-bridge`），服务端给的
  `spec`/包名被忽略，策略被篡改也不能下发任意代码。

## 测试

```bash
# 验签：不需要任何外部服务，16 个用例
node test/oidc.test.mjs

# 插件策略：不需要任何外部服务，10 个用例
node test/plugins.test.mjs

# WorkBuddy 共享：自带假网关，不碰网络，13 个用例
node test/workbuddy.test.mjs

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
