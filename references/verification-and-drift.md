# 验收与回归（P7～P8）

## 层级（沿用上游定义）

| 层级 | 含义 | 本 Skill 的证据 | 不算数的证据 |
|---|---|---|---|
| S1 能生成 | 相同输入下，生成代码算出的值与浏览器一致 | `pf verify` 全部通过 | 能跑出一个值 |
| S2 被接受 | 服务端没有拒绝 | `run-check` 中 `rejected=0` 且 `target_ok>0` | HTTP 200 |
| S3 命中目标 | 响应是要的数据，结构符合预期 | `items>0` 且 `--expect-keys` 全部存在 | 响应非空 |
| S4 可持续 | 多目标、连续、续期、跨天都成立 | 多次运行报告的汇总 | 单次通过 |

`pf run-check` 单次运行最多报 S3，报告里明确写出 S4 未断言。

## 在线验收

```bash
pf run-check out/shop_client --op items --max-pages 2 --expect-keys id,title,price --report reports/check-items.json
```

- 页数要少：验收只证明链路成立，不是采集。默认 2 页。
- 运行前确认：控制组（浏览器里同样的操作）此刻能成功；一次性值没被用过；账号额度够。不满足就不发（上游“发送前过门禁”）。
- 结果按 `transport_error / rejected / accepted / target_ok` 分类，不合并。
- 出现 `rejected` 时停止，不重复运行“再试试”。先对照同期成功样本定层：
  - 业务码指向签名错误 → 回到 P4，检查 fixtures 是否覆盖了这个输入组合；
  - 离线一致但被拒 → 上游链路 B/E（会话绑定、环境读值、时序）；
  - 只有本地失败、浏览器正常 → 上游链路 C（传输），先查 `pf fp-check`。

## 报告格式

```json
{
  "op": "items", "status": "ok", "pages": 2, "items": 40,
  "counts": {"transport_error": 0, "rejected": 0, "accepted": 0, "target_ok": 3},
  "missing_keys": [], "level": "S3",
  "level_note": "S3 = ... S4 ... is not asserted here.",
  "attempts": [{"op": "session", "url": "...", "result": "target_ok", "status": 200, "elapsed_ms": 4}, ...]
}
```

报告里有完整 URL（含 query），可能包含 token，放在 `reports/`（已在 `.gitignore` 中）。

## 改版检测

```bash
pf drift spec.yaml captures/new.json     # 规格 vs 新抓包
pf drift spec.old.yaml spec.new.yaml     # 规格 vs 规格
```

| 代码 | 级别 | 含义 |
|---|---|---|
| D001 | error | 抓包里出现规格没有的 query 参数 |
| D002 | error | 常量值变了 |
| D003 | error | 出现新的自定义请求头 |
| D004 | error | 出现新的正文字段 |
| D005 | warning | 规格里的必填字段在抓包里缺失 |
| D006 | error | 成功规则的路径在响应里不存在 |
| D007 | warning | 列表路径不存在（可能是错误响应） |
| D010 | warning | UA 变了 |
| S001～S008 | warning/info | 两份规格之间的接口、字段、传输、签名器变化 |

有 error 时退出码为 1，适合放进定时任务：每天抓一份小样本做 drift，有变化再安排人工处理。

## 回归流程

1. `pf drift` 定位差异，只处理变化的部分。
2. 新字段按 P3 消解；常量变化先确认是版本号还是业务值。
3. 签名器有变化（上游 SDK 哈希变了，或 fixtures 不再通过）就重做 P4，并更新 `verified`。
4. `pf gen --force` 重新生成，`pf run-check` 重新验收，报告和旧报告放在一起保存。
5. 在 spec 的 `meta.upstream.scope` 更新日期与范围。

## 全部检查代码

| 前缀 | 来源 |
|---|---|
| `L0xx` | `pf lint`：schema（L000）、授权（L001）、字段（L010～L019）、签名器（L020、L060～L063）、分页（L040～L044）、依赖（L050～L052）、传输与合规（L070～L073） |
| `FPxxx` | `pf fp-check`，见 [transport-fingerprint.md](transport-fingerprint.md) |
| `Dxxx` / `Sxxx` | `pf drift` |
