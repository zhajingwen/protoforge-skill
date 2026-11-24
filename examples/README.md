# 示例：本地演示站点全流程

`demo-site/server.py` 是一个本地练习站点，模拟常见的签名 API：

| 接口 | 特点 |
|---|---|
| `GET /api/session` | 下发 Cookie `sid` 和绑定它的 `token` |
| `GET /api/items` | query 带 `ts/nonce/token`，请求头 `X-Sign` 是 HMAC-SHA256；页码分页 + `has_more` |
| `POST /api/search` | JSON 正文，`X-Sign` 对规范化正文做摘要；游标分页，首页 `"cursor": null` |

业务错误都是 HTTP 200 + 非零业务码：4001 签名错、4002 时间戳过期、4003 nonce 重放、4010 无会话。

## 文件

```
demo-site/server.py          演示站点
demo-site/make_capture.py    扮演“页面”，生成 camoufox-reverse-mcp 导出格式的抓包
demo/capture.json            抓包（含原值，相当于 include_sensitive=True）
demo/capture.redacted.json   同一抓包的默认脱敏导出
demo/spec.yaml               消解完成的规格
demo/signers/items_hmac.py   python 签名器（R1）
demo/signers/search_sign.js  node 签名器（R2）
demo/fixtures/demo.fixtures.json   pf fixtures 生成的离线样本
```

## 步骤

先在仓库根目录建环境并激活，下面的命令都在这个环境里执行：

```bash
uv sync
source .venv/bin/activate        # 不想激活的话，每条命令前加 uv run --project <仓库根目录>
```

然后在 `examples/demo` 下执行：

```bash
# 0. 启动站点（另开终端，或放后台）
python ../demo-site/server.py --port 8799

# 1. 草稿：看 import 的分类结果
pf import capture.json -o /tmp/draft.yaml --name demo_shop
#    - ts → timestamp，page/cursor → pagination
#    - token → upstream(api_session.data.token)，自动加 depends_on
#    - nonce、X-Sign → unknown（需要上游判断）
pf lint /tmp/draft.yaml --stage draft

# 2. 脱敏抓包只能得到 unknown，提示重新导出
pf import capture.redacted.json -o /tmp/draft_r.yaml

# 3. 最终规格与离线验签
pf lint spec.yaml
pf fixtures spec.yaml capture.json --op items --op search -o /tmp/fx.json
pf verify spec.yaml --fixtures /tmp/fx.json

# 4. 指纹检查：把 impersonate 改成 chrome131 试试
sed 's/impersonate: firefox147 /impersonate: chrome131 /' spec.yaml > /tmp/bad.yaml
pf fp-check /tmp/bad.yaml --capture capture.json        # FP003

# 5. 生成并运行 curl_cffi 客户端
pf gen spec.yaml --target curl_cffi -o /tmp/demo_cc --fixtures fixtures/demo.fixtures.json
cd /tmp/demo_cc
python verify_offline.py fixtures/demo.fixtures.json
python main.py items --out data/items.jsonl --report reports/items.json     # 45 条
python main.py search --input keyword=misc --out data/search.jsonl          # 15 条
DEMO_SIGN_KEY=wrong python main.py items                                    # 业务拒绝即停
cd -

# 6. 生成并运行 Scrapy 项目
pf gen spec.yaml --target scrapy -o /tmp/demo_sc
cd /tmp/demo_sc && scrapy crawl items && scrapy crawl search -a keyword=misc && cd -

# 7. 在线验收与改版检测
pf run-check /tmp/demo_cc --op items --max-pages 2 --expect-keys id,title,price
pf drift spec.yaml capture.json
```

站点换端口时，用 `PF_BASE_URL=http://127.0.0.1:<端口>` 覆盖规格里的 `base_url`，不用改规格。

## 换成真实目标时

1. P1 用 camoufox-reverse-mcp 抓包并 `export_network_capture(include_sensitive=True, include_body=True)`，导出到私有工作区的 `captures/`。
2. `pf import` 得到草稿，按 [evidence-to-spec.md](../references/evidence-to-spec.md) 消解 unknown；签名交给 hello-js-reverse-skill。
3. 之后的步骤与上面相同。`meta.authorization` 写明授权来源与范围。
