# ProtoForge Skill

**把逆向取证结论变成可运行、可验证的协议爬虫。**

ProtoForge 是一个 Agent Skill（Claude Code、Codex、Cursor 等兼容 SKILL.md 的工具都能用），外加一个小型命令行 `pf`。它接在 [hello_js_reverse_skill](https://github.com/WhiteNightShadow/hello_js_reverse_skill) 和 [camoufox-reverse-mcp](https://github.com/WhiteNightShadow/camoufox-reverse-mcp) 后面，负责逆向之后的那一段：

```
camoufox-reverse-mcp 抓包 / HAR
        │  pf import
        ▼
spec.draft.yaml ──(上游 Skill 消解 unknown、还原签名)──▶ spec.yaml + signers/
        │  pf lint · pf fixtures · pf verify --record · pf fp-check
        ▼
pf gen ──▶ curl_cffi 客户端  或  Scrapy 项目（scrapy-impersonate）
        │  pf run-check
        ▼
验收报告（S1/S2/S3、结果分类）   ……改版时 pf drift
```

## 为什么要有它

hello_js_reverse_skill 已经把“签名在哪、走哪条链路、做到什么证据才算数”讲得很完整，它的交付模板是通用的 requests / Node 采集程序。实际工程里还缺这几块：

| 缺口 | ProtoForge 的做法 |
|---|---|
| 逆向结论散落在对话和笔记里，代码靠手写 | **协议规格 `spec.yaml`** 作为唯一交接物，JSON Schema 约束，可审可 diff |
| 抓包到规格要人工逐字段分析 | `pf import` 读 camoufox 导出或 HAR，按多样本自动分类字段，识别上游回显值（token/csrf） |
| requests 的 TLS 指纹与浏览器不一致 | 生成代码一律走 **curl_cffi**，`pf fp-check` 检查 impersonate / UA / Client Hints 三者一致（Camoufox=Firefox 的坑） |
| 没有 Scrapy 交付 | 生成完整 **Scrapy 项目**：impersonate 下载器、重建式重试（不重放旧签名）、业务拒绝即停、JSONL 去重 |
| 签名接入方式各写各的 | 统一的**签名器契约**：python（R1）/ node（R2、R3）/ http（R4、R5） |
| “能跑”和“被接受”混为一谈 | `pf verify` 离线逐字比对（S1，报第一个不同字符），`pf run-check` 在线有界验收（S2/S3），结果四类分开计数 |
| 改版后不知道哪里变了 | `pf drift` 比较规格与新抓包、或两份规格 |
| 闸门靠自觉 | `pf lint`：未授权、未消解字段、未验证签名器、硬编码凭据、无界分页、缺限速都会阻止生成 |

## 快速体验（本地演示站点，不访问外网）

```bash
uv sync                                          # 按 uv.lock 建 .venv：pf + curl_cffi + scrapy + scrapy-impersonate + pytest
export PF_HOME="$PWD"                            # 仓库根目录；在别处运行时用 uv run --project "$PF_HOME"
cd examples/demo
uv run python ../demo-site/server.py --port 8799 &   # 带签名、会话、分页的本地练习站点

uv run pf import capture.json -o /tmp/draft.yaml --name demo_shop   # 看草稿怎么分类、哪些是 unknown
uv run pf lint spec.yaml                                             # 已消解的最终规格
uv run pf verify spec.yaml --fixtures fixtures/demo.fixtures.json    # 离线验签：python + node 两种签名器
uv run pf gen spec.yaml --target curl_cffi -o /tmp/demo_cc
uv run python /tmp/demo_cc/main.py items --out /tmp/demo_cc/data/items.jsonl
uv run pf gen spec.yaml --target scrapy -o /tmp/demo_sc && (cd /tmp/demo_sc && uv run --project "$PF_HOME" scrapy crawl search)
uv run pf run-check /tmp/demo_cc --op items --expect-keys id,title,price
```

完整步骤与说明见 [examples/README.md](examples/README.md)。

## 安装为 Skill

```bash
git clone <本仓库> ~/.claude/skills/protoforge          # Claude Code（个人级）
# 或项目级：<项目>/.claude/skills/protoforge
# Codex 等：<项目>/.agents/skills/protoforge
(cd ~/.claude/skills/protoforge && uv sync)               # 建环境；之后 uv run --project ~/.claude/skills/protoforge pf ...
```

建议同时安装上游：

- [hello_js_reverse_skill](https://github.com/WhiteNightShadow/hello_js_reverse_skill)：签名定位、补环境、对照实验方法论
- [camoufox-reverse-mcp](https://github.com/WhiteNightShadow/camoufox-reverse-mcp)：浏览器取证（抓包导出、Hook、插桩、`verify_signer_offline`）

Agent 读取 `SKILL.md` 后，会在“把接口写成爬虫”“生成 scrapy/curl_cffi 代码”“接口改版回归”这类任务里自动使用本 Skill，并在需要逆向时交给上游。

## 命令

| 命令 | 作用 |
|---|---|
| `pf import <capture> -o spec.draft.yaml` | 从 camoufox 导出或 HAR 生成草稿规格 |
| `pf fixtures <spec> <capture> --op X [--op Y] -o f.json` | 从未脱敏抓包生成签名样本 |
| `pf lint <spec> [--stage draft]` | 闸门检查 |
| `pf fp-check <spec> [--capture c.json]` | 指纹一致性 |
| `pf verify <spec|project> --fixtures f.json [--record]` | 离线验签（S1），通过后可写回记录 |
| `pf gen <spec> --target curl_cffi|scrapy -o out/` | 生成项目（内置 lint 闸门） |
| `pf run-check <project> --op X [--max-pages 2] [--expect-keys a,b]` | 在线有界验收（S2/S3） |
| `pf drift <spec> <capture|spec>` | 改版检测 |
| `pf targets` | 当前 curl_cffi 支持的 impersonate 目标 |

## 目录

```
SKILL.md                 Agent 读取的方法论：阶段、闸门、纪律、收口
references/              按需参考（规格格式、证据到规格、签名器契约、指纹、生成目标、验收与回归）
protoforge/              pf 命令行与生成器
  schema/                spec JSON Schema
  runtime/               复制进每个生成项目的运行时（仅标准库 + curl_cffi）
  templates/             curl_cffi 与 Scrapy 模板
examples/                本地演示站点、抓包、规格、签名器、fixtures
evals/                   Agent 行为评测用例
tests/                   端到端测试（对本地演示站点）
```

## 测试

```bash
uv sync          # 首次或依赖变化后；开发依赖在 [dependency-groups].dev，默认一起安装
uv run pytest -q
```

依赖变更用 `uv add <包>`（运行依赖）或 `uv add --dev <包>`（开发依赖），会同时更新 `pyproject.toml` 和 `uv.lock`。只想要命令行、不要开发依赖：`uv sync --no-dev`；生成物需要的运行库可按需加 extra：`uv sync --extra curl` 或 `--extra scrapy`。

测试覆盖：草稿分类与上游值识别、脱敏抓包、指纹建议与冲突、lint 闸门、`--record` 保留格式、篡改签名器后的逐字差异、curl_cffi 与 Scrapy 项目对演示站点的完整运行、业务拒绝即停、S2/S3 判定、drift。

## 使用边界

- 仅用于**自有或已获授权**的接口。`meta.authorization` 为空时不会生成代码。
- 默认遵守 robots.txt、强制限速、并发为 1；放宽要在规格里写明原因。
- 不提供绕过验证码、账号风控或付费墙的能力；遇到频控、验证页、账号受限时，生成的代码会停止当批。
- 凭据只走环境变量；抓包与含真实值的样本不进仓库（`.gitignore` 已覆盖）。

## 致谢与许可

方法论术语（S0～S4 成功层级、R0～R6 路线、结果分类、链路 A～K）来自 [hello_js_reverse_skill](https://github.com/WhiteNightShadow/hello_js_reverse_skill)；抓包导出格式来自 [camoufox-reverse-mcp](https://github.com/WhiteNightShadow/camoufox-reverse-mcp)。本仓库未复制上游代码，详见 [NOTICE](NOTICE)。

Apache License 2.0。
