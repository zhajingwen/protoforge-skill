# 生成目标（P6）

```bash
pf gen spec.yaml --target curl_cffi -o out/shop_client [--fixtures fixtures/x.json]
pf gen spec.yaml --target scrapy    -o out/shop_scrapy [--fixtures fixtures/x.json]
```

`pf gen` 先跑完整 lint，有错误就不生成。目标目录非空时需要 `--force`（只覆盖生成文件，不删除你的 `data/`、`reports/`）。

## 两种目标共用的部分

| 文件 | 作用 | 能否手改 |
|---|---|---|
| `spec.yaml` | 规格副本，项目的事实来源 | 改规格要改原件，再重新生成 |
| `api.py` | 每个接口一个 `build_<op>(ctx, cursor=None, **inputs)`，以及 `TRANSPORT / SESSION / SIGNERS / OPS` | 否（会被覆盖） |
| `pf_runtime.py` | 取值来源、签名适配、限速、成功规则、分页、结果分类、离线验证 | 否；发现缺陷改本 Skill 的 runtime |
| `pf_node_bridge.js` | node 签名器桥接 | 否 |
| `signers/` | 签名器（从规格目录复制） | 改原件后重新生成 |
| `verify_offline.py` | 用 fixtures 做离线比对（S1） | 否 |

构造器是普通 Python 函数，可以在别的程序里直接复用：

```python
import api, pf_runtime as rt
ctx = api.new_context()
req = api.build_items(ctx, cursor=1, keyword="pf")   # 依赖值需先放进 ctx.upstream
print(req.url, req.headers)
```

## curl_cffi 目标

```text
out/shop_client/
├── main.py            # 命令行：列出接口、运行、输出 JSONL 与报告
├── api.py  pf_runtime.py  pf_node_bridge.js  signers/
├── verify_offline.py  spec.yaml  requirements.txt  README.md  .gitignore
```

```bash
python main.py --list
python main.py items --input keyword=pf --max-pages 3 --out data/items.jsonl --report reports/items.json
```

- 依赖接口自动按顺序先执行，提取的值写入上下文。
- 只对幂等方法做有界重试（429/5xx/连接错误），每次重试都重新构造请求。
- 业务拒绝立即停止并在报告里记 `rejected`，不重试。
- 报告分开计数 `transport_error / rejected / accepted / target_ok`，并列出每次尝试。

## Scrapy 目标

```text
out/shop_scrapy/
├── scrapy.cfg
├── <name>/
│   ├── settings.py       # 来自 transport/compliance：UA、默认头、限速、并发、robots、impersonate 下载器
│   ├── base_spider.py    # 依赖链、分页、重建式重试、业务拒绝即停、结果计数
│   ├── spiders/<op>.py   # 每个带 items 的接口一个 spider
│   ├── pipelines.py      # JSONL + item_key 去重
│   └── api.py  pf_runtime.py  pf_node_bridge.js  signers/
├── verify_offline.py  spec.yaml  requirements.txt  README.md
```

```bash
scrapy crawl items -a keyword=pf -a max_pages=3     # 输出 data/items.jsonl
```

设计取舍：

- **下载器**：`scrapy_impersonate.ImpersonateDownloadHandler`，每个请求带 `meta["impersonate"]`，指纹与 curl_cffi 目标一致。需要 asyncio reactor（settings 已设置）。
- **重试**：关闭 Scrapy 自带的 RetryMiddleware（它会原样重放带旧签名的请求），在 `base_spider` 里遇到可重试状态时重新构造请求。
- **顺序**：依赖接口和翻页都是串行链；需要并发时，按输入拆成多个 spider 运行，而不是在一条分页链里并发。
- **Cookie**：`PF_COOKIES` 只注入首个请求，之后由 Scrapy 的 Cookie 中间件维护。
- **签名**：在回调线程里同步执行。node 签名器每次起进程，开销较大；量大时改 http 签名器。
- **robots**：默认遵守；robots.txt 请求不走 impersonate 下载器。
- **停止原因**：`business_rejected`、`http_<code>`、`transport_error`、`cursor_loop`、`non_json_response` 会写进 `finish_reason`，统计项 `protoforge/counts` 记录结果分类。

## 扩展点

需要规格表达不了的行为时，按以下顺序选：

1. **签名器**：任何与请求内容相关的计算都放这里，包括加密正文后整体替换的情况（签名器返回加密后的字段）。
2. **新的 source 类型或分页模式**：改本 Skill 的 `pf_runtime.py` 与 `codegen.py`，加测试，让所有项目受益。
3. **在生成项目外包一层**：例如响应解密、字段清洗，放在调用 `rt.collect` 或 pipeline 之后的自有代码里。

不推荐直接改生成的 `api.py`：下次 `pf gen` 会覆盖，而且规格和代码会不一致。
