---
name: protoforge
description: >
  把逆向取证结论固化成协议规格（spec.yaml），再生成可运行、可验证的 curl_cffi 客户端或 Scrapy 项目。
  任务涉及“把接口写成协议爬虫/采集程序”“生成 scrapy 或 curl_cffi 代码”“抓包结果转代码”“签名函数接入爬虫”
  “TLS 指纹与 UA 不一致”“接口改版后回归”时使用，即使用户没有提到 spec。
  签名、动态 Cookie、混淆与 JSVMP 的定位和还原交给 hello-js-reverse-skill；浏览器取证使用 camoufox-reverse-mcp。
  仅用于自有或已授权的接口。
metadata:
  version: "0.1.0"
  requires: "Python 3.10+ 与 uv；pf CLI（在本 Skill 目录 uv sync）；生成物依赖 curl_cffi，Scrapy 目标另需 scrapy 与 scrapy-impersonate；node 签名器需要 Node.js"
  upstream: "hello-js-reverse-skill v3.16+（方法论）；camoufox-reverse-mcp v1.8+（取证，可选）"
---

# ProtoForge：从逆向证据到协议爬虫

本 Skill 只管逆向之后的那一段：**证据 → 规格 → 代码 → 验收 → 回归**。它不负责找签名，也不记录任何站点规则。

| 环节 | 谁负责 | 产物 |
|---|---|---|
| 抓包、Hook、插桩、补环境、定位与还原签名 | hello-js-reverse-skill + camoufox-reverse-mcp | 抓包导出、签名函数、实验台账 |
| 字段分类、协议规格、闸门 | **本 Skill**（`pf import / lint / fp-check`） | `spec.yaml` |
| 离线验签、代码生成、在线验收、改版检测 | **本 Skill**（`pf verify / gen / run-check / drift`） | curl_cffi 或 Scrapy 项目、验收报告 |

核心约定：**`spec.yaml` 是逆向和编码之间唯一的交接物。** 代码从规格生成，不从抓包直接手写；改协议先改规格再重新生成。规格可审、可 diff，改版时只动差异。

## 启动

1. 在本 Skill 目录执行 `uv sync`（按 `uv.lock` 建好 `.venv`，含开发依赖），之后用 `uv run pf ...` 调用；确认 `uv run pf --version` 可用。在其他目录调用时用 `uv run --project <本 Skill 目录> pf ...`。
2. 读需求工作区里已有的 `spec.yaml`、`captures/`、`fixtures/`、`reports/`，能复用就复用，不重抓。
3. 新任务先用 [示例](examples/README.md) 的五条命令热身一次，确认环境和生成物能跑通（本地演示站点，不访问外网）。

## 阶段与闸门

每一阶段有一道闸门。闸门没过，不进入下一阶段，也不用 `--force` 或手改生成代码绕过去。

| 阶段 | 做什么 | 闸门（过了才继续） |
|---|---|---|
| P0 接入 | 记录授权与范围、目标字段、数据量与频率、交付形态（curl_cffi / Scrapy） | `meta.authorization` 有实际内容；能说清“要哪些字段、到什么层级算完成” |
| P1 取证 | 用 MCP 对每个目标接口抓 **2～3 个同操作不同输入** 的样本，导出到私有工作区 | 导出无 `pending/dropped`，正文完整；样本覆盖翻页和至少两个不同输入 |
| P2 草稿 | `pf import captures/x.json -o spec.draft.yaml` | 草稿里每个 `unknown` 都列进待办 |
| P3 消解 | 逐个解决 `unknown`：要不要发、从哪来、谁来算；签名写进 `signers/` | `pf lint --stage draft` 无错误，且 0 个 `unknown` |
| P4 验签 | `pf fixtures` 生成样本，`pf verify --record` 离线比对 | 全部样本通过，签名器 `verified.status=passed`（到达 S1） |
| P5 指纹 | `pf fp-check spec.yaml --capture captures/x.json` | 无 `FP` 错误：impersonate 与 UA 同族、版本接近、无跨族请求头 |
| P6 生成 | `pf gen spec.yaml --target curl_cffi|scrapy -o out/` | `pf lint` 全部通过（gen 内置该闸门） |
| P7 验收 | `pf run-check out/ --op <op> --max-pages 2 --expect-keys ...` | 每个目标接口到达 S3；结果分类无 `rejected`；未运行的层级不宣称 |
| P8 交付 | 交付项目、规格、验收报告和收口五项；登记回归方式 | 见“交付与收口” |

详细做法：P1～P3 见 [证据到规格](references/evidence-to-spec.md)，P4 见 [签名器契约](references/signer-contract.md)，P5 见 [传输指纹](references/transport-fingerprint.md)，P6 见 [生成目标](references/codegen-targets.md)，P7～P8 见 [验收与回归](references/verification-and-drift.md)，字段语法见 [规格格式](references/spec-format.md)。

## P3：unknown 怎么消解

`pf import` 只按样本做分类，拿不准的一律标 `unknown`，hint 里写明它看到了什么。消解靠证据，不靠猜：

| 草稿里的样子 | 先做什么 | 落到 spec 的写法 |
|---|---|---|
| 每次都变、像哈希的值（`X-Sign`、`sign`） | 上游 **链路 A**：先重放成功请求，删掉这一项看服务端认不认 | 不需要 → 删掉（R0）；需要 → `source: signer` |
| 每次都变、16 位左右随机串 | 同上；服务端只查唯一性时就是 nonce | `source: nonce, format: hex16` |
| 草稿已标 `upstream` 的值（token、csrf） | 确认来源接口和提取路径，写进 `depends_on` | `source: upstream, op, field` |
| 时间戳 | 确认单位、是否允许偏差、是否参与签名 | `source: timestamp, unit: ms` |
| 被脱敏（`[REDACTED]`） | 用 `include_sensitive=True` 重新导出到私有目录 | 重新 import |
| 登录态、Authorization | 不写进规格；从环境变量或登录接口来 | `source: env` 或上游 op；Cookie 用 `session.cookies_env` |
| 嵌套 JSON 字段 | 判断是否由签名或业务决定，必要时拆平 | 按字段逐个声明 |

签名定位和还原的全部方法（链路 A～K、路线 R0～R6、对照实验）在上游 Skill 里，本 Skill 不复述。拿到签名函数后按 [签名器契约](references/signer-contract.md) 封装：

| 上游路线 | 签名器 `kind` | 说明 |
|---|---|---|
| R1 纯算法 | `python` | 首选，无运行时依赖 |
| R2 片段执行 / R3 补环境 | `node` | 抽出的函数或 jsdom 环境包放 `signers/`，经 `pf_node_bridge.js` 调用 |
| R4 浏览器级运行时 / R5 页面出值 | `http` | 签名由外部服务提供（如常驻 Camoufox 页），在 spec 写明谁维持它 |
| R6 页面内请求 | 不适用 | 交还上游的浏览器模板，本 Skill 不生成 |

## 选择生成目标

| 情况 | 选择 |
|---|---|
| 接口少、一次性或要嵌入别的服务、需要细粒度控制 | `curl_cffi` |
| 量大、要调度、去重、断点、并发控制、pipeline | `scrapy`（经 scrapy-impersonate 走 curl_cffi） |
| 用户已指定 | 按用户指定 |

两种目标共用同一套 `api.py`（请求构造器）、`pf_runtime.py`（取值来源、签名适配、限速、分页、结果分类）和 `signers/`，行为一致。

## 纪律

- **闸门不绕过。** lint 报错就改 spec，不改生成代码，不加 `--force` 跳过验签。
- **凭据不进规格和代码。** Cookie、Authorization、密钥一律走环境变量；`captures/` 和含真实值的 `fixtures/` 不提交。
- **签名每次现算。** 生成代码的重试会重建请求，时间戳、nonce、签名都是新的，不重放旧签名。
- **业务拒绝即停。** HTTP 200 但业务码不符视为拒绝，立即停止当批，回到上游链路 B 定层，不靠重试碰运气。
- **结果分类不合并。** `transport_error / rejected / accepted / target_ok` 分开记，超时不是拒绝。
- **层级按证据报。** 离线全过只是 S1；`run-check` 一次通过最多是 S3；S4（多目标、连续、续期、跨天）要重复运行，不在单次报告里宣称。
- **限速与 robots 默认开启。** `rate_limit` 必填；关掉 `obey_robots` 要在 `compliance.notes` 写原因。
- **结论带范围。** spec 的 `meta.upstream.scope` 和签名器的 `verified.scope` 写明接口、版本、日期和验证方式。

## 交付与收口

交付物：生成的项目目录（含 `spec.yaml`）、`fixtures/` 的脱敏副本或生成方法、`reports/` 下的验收报告、运行说明与已知限制。

收口写五项（与上游格式一致）：

1. **到达层级**：S1/S2/S3，各接口分别写，附报告路径。
2. **当前路线与外部依赖**：签名器路线（R1～R5），是否依赖外部会话或签名服务，谁提供、谁续期。
3. **适用范围**：接口、参数组合、账号类型、验证日期。
4. **结论强度**：观察 / 支持 / 证明，对应哪份证据。
5. **失效条件**：哪些变化会让它失效（SDK 哈希变化、新增参数、指纹策略变化），以及用 `pf drift` 检测的方式。

## 改版回归

站点改版时先检测，不先改代码：

1. 抓一份新样本，`pf drift spec.yaml captures/new.json`：新增参数、常量变化、新请求头、成功路径缺失都会报出来。
2. 有差异时回到 P2/P3：`pf import` 新草稿，`pf drift old.yaml new.yaml` 比较两份规格，只消解变化的字段。
3. 签名器变了就重做 P4；然后重新 `pf gen` 和 `pf run-check`。

## 按需参考

| 当前需要 | 参考 |
|---|---|
| spec 每个字段的写法 | [spec-format.md](references/spec-format.md) |
| MCP 取证顺序、样本设计、unknown 消解 | [evidence-to-spec.md](references/evidence-to-spec.md) |
| 签名器接口、python/node/http 三种接法 | [signer-contract.md](references/signer-contract.md) |
| impersonate、UA、请求头一致性 | [transport-fingerprint.md](references/transport-fingerprint.md) |
| 生成项目的结构、运行和扩展点 | [codegen-targets.md](references/codegen-targets.md) |
| S 层级、报告格式、drift 与错误码 | [verification-and-drift.md](references/verification-and-drift.md) |
| 跑通一遍完整流程 | [examples/README.md](examples/README.md) |
