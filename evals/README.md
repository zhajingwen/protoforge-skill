# Agent 行为评测

每个用例是一段给 Agent 的提示（`prompt.md`）和判定断言（`case.yaml`）。评测的是 Agent 是否遵守 SKILL.md 的闸门与纪律，不是 pf 的代码正确性（那由 `tests/` 覆盖）。

运行方式：在装有本 Skill 的 Agent 中，用一个新会话发送 `prompt.md`，由独立评审（人工或另一个 Agent）按 `case.yaml` 的断言逐条判定通过/不通过。用例只依赖 `examples/` 的本地演示站点。
