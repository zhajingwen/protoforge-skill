# 规格格式（spec.yaml，protoforge: 1）

机器可读的约束在 `protoforge/schema/spec.schema.json`，`pf lint` 先做 schema 校验，再做语义闸门。本文解释每一块的含义与取舍。完整示例见 `examples/demo/spec.yaml`。

## 顶层

```yaml
protoforge: 1          # 规格版本
meta: {...}            # 名称、目标、授权、证据、上游结论
transport: {...}       # 指纹、UA、默认头、限速、重试、代理
session: {...}         # 登录态从哪来
compliance: {...}      # robots、并发、说明
signers: {...}         # 签名器声明与验证记录
operations: {...}      # 接口
```

## meta

| 字段 | 必填 | 说明 |
|---|---|---|
| `name` | 是 | 小写下划线，作为 Scrapy 包名 |
| `base_url` | 是 | `scheme://host[:port]`。运行时可用 `PF_BASE_URL` 覆盖（测试环境、预发） |
| `authorization` | 是 | 谁授权、范围是什么。空字符串 lint 报 `L001` |
| `evidence` | 否 | 抓包、实验台账的相对路径 |
| `upstream.route` | 否 | 上游给出的交付路线 R0～R6 |
| `upstream.level` | 否 | 当前已证明的层级 S0～S4 |
| `upstream.scope` | 否 | 结论适用的接口、版本、日期 |

## transport

| 字段 | 说明 |
|---|---|
| `impersonate` | curl_cffi 的浏览器目标，如 `firefox147`、`chrome131`、`safari184`。写 `auto` 时按 UA 选最接近的。`pf targets` 列出已安装版本支持的值 |
| `user_agent` | 与 `impersonate` 同族同代。Camoufox 抓的包通常是 Firefox UA |
| `default_headers` | 所有请求都带的头（Accept、Accept-Language 等）。不要放 Cookie/Authorization（`L072`） |
| `timeout` | 秒 |
| `proxy_env` | 代理地址所在的环境变量名，值不写进规格 |
| `verify_tls` | 默认 true |
| `rate_limit.rps` / `jitter` | 必填。每秒请求数与抖动比例；> 5 会警告 |
| `retry` | `max_attempts`（总尝试次数）、`statuses`、`idempotent_only`（默认只重试 GET/HEAD/OPTIONS） |

## session 与 compliance

```yaml
session:
  cookies_env: PF_COOKIES      # "a=1; b=2"，只在首个请求注入，之后由会话维护
  cookie_names: [sid]          # 仅记录名字，便于核对
compliance:
  obey_robots: true            # Scrapy 的 ROBOTSTXT_OBEY
  max_concurrency: 1
  notes: "..."                 # 关闭 robots 或提高频率时写原因
```

## signers

```yaml
signers:
  items_hmac:
    kind: python               # python | node | http
    module: signers/items_hmac.py   # 相对 spec 所在目录，不能含 ..
    entry: sign                # 导出函数名
    outputs: [x_sign]          # 返回字典里的键
    route: R1                  # 上游路线
    verified: {status: passed, method: ..., samples: ..., date: ..., scope: ...}
```

`kind: http` 用 `url_env` 指定签名服务地址所在的环境变量。`verified.status` 不是 `passed` 时 lint 报 `L020`，生成被阻止。签名器接口见 [signer-contract.md](signer-contract.md)。

## operations

```yaml
operations:
  items:
    description: ...
    method: GET
    path: /api/items
    depends_on: [session]          # 先跑哪些接口
    query:   {<name>: <field>}     # 顺序即发送顺序
    headers: {<name>: <field>}
    body:    {type: json|form|none, fields: {<name>: <field>}}
    extract: {token: data.token}   # 供下游 upstream 引用
    success: {path: code, equals: 0}   # 或 in: [0, 200]
    items: data.items              # 列表路径；空字符串表示顶层数组
    item_key: id                   # 去重键
    pagination: {...}
```

路径语法统一用点号：`data.items`、`data.0.id`。

### 字段（field）的 source

| source | 参数 | 生成的取值 |
|---|---|---|
| `const` | `value` | 固定值。看起来像凭据的常量会被 `L012` 拦下 |
| `input` | `required`（默认 true）、`default` | 调用方传入（CLI `--input k=v`，Scrapy `-a k=v`）。可选且为 None 时不发送 |
| `pagination` | — | 当前页码、偏移或游标。每个分页接口恰好一个 |
| `timestamp` | `unit: ms|s` | 当前时间 |
| `nonce` | `format: hex8|hex16|hex32|uuid4|digits6|digits8|digits13` | 每次新随机 |
| `upstream` | `op`、`field` | 依赖接口 `extract` 出的值；`op` 必须在 `depends_on` 中（`L015`） |
| `env` | `var`、`required` | 环境变量，用于账号凭据等 |
| `signer` | `signer`、`output` | 在其余字段组装完后由签名器填入 |
| `unknown` | `hint` | 草稿专用；最终规格不允许（`L010`） |

通用可选键：

- `type: int`：发送前转为整数，用于 JSON 正文里的数字（时间戳、游标）。
- `nullable: true`：仅正文字段；值为 None 时仍发送 `null`（有些签名把 `"cursor": null` 算进去）。
- `evidence`、`hint`：给人看的说明，生成时忽略。

### pagination

| 字段 | 说明 |
|---|---|
| `mode` | `page` / `offset` / `cursor` / `none` |
| `param` | 分页字段名（与 `source: pagination` 的字段一致） |
| `start` | 首个值：page 默认 1，offset 默认 0，cursor 默认不发送 |
| `step` | offset 每页增量；不填按本页条数 |
| `next_path` | cursor 模式下一游标的路径；为 null 或空串时结束 |
| `has_more_path` | 显式结束标志（必须是布尔值），优先于空页判断 |
| `stop_on_empty` | 默认 true |
| `max_pages` | 必填（`L042`），不允许无界抓取 |

游标重复会立即停止，避免死循环。

## 与上游术语的对应

- S0～S4、R0～R6、结果分类沿用 hello-js-reverse-skill 的定义，语义不变。
- 上游的“这个参数到底要不要算”（链路 A）的结论，直接体现在字段是否出现、source 是什么。删掉的参数不出现在规格里，并在 `evidence` 或 `notes` 记录删减实验。
