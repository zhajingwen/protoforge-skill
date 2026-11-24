# 证据到规格（P1～P3）

## P1 取证：用 camoufox-reverse-mcp 抓什么

目标不是“抓到一个能用的请求”，而是**让每个字段都能被分类**。同一个字段只出现一次，就分不清它是常量、输入还是每次都变的签名。

```text
check_environment()
launch_browser()
network_capture(action="start", capture_body=True)
navigate(url="<目标页>")
# 同一操作做 2~3 次、换不同输入：翻到第 2 页、换一个关键词、刷新后再做一次
network_capture(action="stop", wait_timeout_ms=3000)
list_network_requests(limit=100, after_id=0)          # 增量读取，确认目标请求都在
export_network_capture(save_path="<工作区>/captures/<任务>-<日期>.json",
                       include_sensitive=True, include_body=True)
```

要点：

- **导出到私有工作区。** `include_sensitive=True` 会带上 Cookie、签名和正文原值，这份文件只用于本地分类和生成 fixtures，不提交。需要分享时另导一份默认脱敏的。
- **看捕获状态。** `pending_requests`、`dropped_requests`、`body_state` 不完整的样本先补齐，残缺正文会让 import 猜错成功规则和列表路径。
- **覆盖依赖链。** 登录、会话、token 下发这类前置请求要一起抓到，import 才能把回显的值认成 `upstream`。
- **记下操作。** 每个样本对应什么用户动作（第几页、什么关键词），写进任务记录，P3 判断 `input` 和 `pagination` 时要用。
- 没有浏览器时，DevTools 或代理导出的 HAR 也能用：`pf import file.har`。

## P2 草稿：pf import 做了什么

```bash
pf import captures/x.json -o spec.draft.yaml --name shop --url-contains /api/
```

1. 只保留 XHR/fetch 或 JSON 响应（`--all` 关闭过滤），按 `方法 + 主机 + 路径` 分组，每组成为一个 operation。出现最多的主机作为 `base_url`。
2. 对每个 query、非浏览器标准头和正文字段，比较组内各样本的值：
   - 所有样本相同 → `const`
   - 13/10 位数字且接近抓包时间 → `timestamp`
   - 名字像页码、偏移、游标 → `pagination`
   - 全是 UUID → `nonce: uuid4`
   - 每次都变的十六进制或 base64 长串 → `unknown`（签名或 nonce，需要上游判断）
   - 其余变化的值 → `input`
   - 只有一个样本 → 能判断的给出猜测并在 hint 注明“single sample”
3. **上游值识别**：字段值（6 位以上）如果先出现在另一个接口的响应里，标为 `upstream`，自动给来源接口加 `extract`、给当前接口加 `depends_on`。
4. 响应猜测：业务码字段（code/errno/ret/status…）作为 `success`，第一个“对象列表”作为 `items`，`id` 类字段作为 `item_key`，`has_more`/`next_cursor` 类字段进入 `pagination`。
5. 传输：取首个 UA，`impersonate` 选同族最接近的版本；Accept、Accept-Language、Origin、Referer 进 `default_headers`；Cookie 只记名字。

草稿是起点。每个 hint 都要核对，`const` 也可能只是样本太少。

## P3 消解：逐字段过一遍

按这个顺序处理，前面的结论会影响后面的判断：

1. **删减**。对带签名或自定义头的接口，先在上游按链路 A 做删减实验：重放一个成功请求，按组去掉候选字段，看服务端是否仍接受。服务端不校验的字段直接从规格删除，并在 `notes` 记下实验（接口、日期、结果）。不发比算出来更稳。
2. **依赖**。确认 `upstream` 字段的来源接口和提取路径；来源是 Set-Cookie 的，用会话自动维护，不需要声明字段。
3. **业务输入与分页**。对照 P1 的操作记录，把用户能改的值设为 `input`（给默认值的设 `required: false`），页码/游标设为 `pagination`。
4. **时间与随机**。时间戳确认单位；nonce 确认格式，服务端只查唯一性时用 `source: nonce`。
5. **签名**。剩下每次都变、删不掉的值交给上游还原。拿到函数后写成签名器（见 [signer-contract.md](signer-contract.md)），字段改为 `source: signer`。
6. **凭据**。Authorization、账号 token 用 `env` 或上游登录接口；Cookie 用 `session.cookies_env`。
7. **成功规则**。确认 `success.path` 与成功值，HTTP 200 不算成功。没有业务码的接口至少要有 `items`，验收时用 `--expect-keys` 检查结构。

完成后：

```bash
pf lint spec.yaml --stage draft     # 允许签名器未验证，其余必须干净
```

## 常见误判

| 现象 | 误判 | 实际 |
|---|---|---|
| token 在两个样本里相同，被判为 const | 固定值 | 会话内不变，换会话就变；看它是否出现在前置响应里 |
| 页码被判为 input | 业务参数 | 名字不常见（如 `pi`、`idx`）；手动改为 pagination |
| 每次都变的值被判为 unknown | 一定是签名 | 可能是 nonce 或客户端追踪 ID，先做删减实验 |
| 正文字段被判为字符串常量 `"10"` | 类型无关 | 签名对 JSON 类型敏感；数字保持数字，必要时加 `type: int` |
| 第一页游标缺失 | 不需要发送 | 浏览器发的是 `"cursor": null` 并参与签名；用 `nullable: true` |
