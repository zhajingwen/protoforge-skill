# 签名器契约（P4）

签名器把上游还原出的签名逻辑，接到生成代码里。所有签名器遵守同一个接口：**输入一个请求视图，返回一个输出字典**。

## 请求视图（view）

构造器先按规格组装好除签名字段以外的所有字段（时间戳、nonce、上游值都已确定），再把视图交给签名器：

```json
{
  "op": "items",
  "method": "GET",
  "path": "/api/items",
  "url": "http://host/api/items",
  "query": [["page", "1"], ["size", "20"], ["ts", "1795511142666"], ["nonce", "be83b7f36e508606"]],
  "headers": {"X-Client-Ver": "3.2.1"},
  "body_type": "none",
  "body": {}
}
```

- `query` 是有序的 `[名, 值]` 列表，保留发送顺序和重复键；值已转为字符串。
- `body` 保留 JSON 原始类型（数字、null）。
- 自身由签名器填写的字段不在视图里。
- 一个请求里同一个签名器只调用一次，多个输出（如 `sign` 和 `x-s-common`）一起返回。

返回值必须是字典，包含 spec 里 `outputs` 声明的每个键。缺键会报错，不会静默发出空签名。

## 三种接法

### python（R1 纯算法）

```python
# signers/items_hmac.py
import hashlib, hmac, os

KEY = os.environ["SHOP_SIGN_KEY"].encode()   # 密钥从环境或私有配置读取

def sign(view: dict) -> dict:
    canonical = "&".join(f"{k}={v}" for k, v in sorted(view["query"]))
    ts = dict(view["query"])["ts"]
    msg = f"{view['method']}\n{view['path']}\n{canonical}\n{ts}".encode()
    return {"x_sign": hmac.new(KEY, msg, hashlib.sha256).hexdigest()}
```

### node（R2 片段执行、R3 补环境）

```javascript
// signers/search_sign.js
exports.sign = async function (view) {
  // 这里放 scripts(action="save") 抽出并裁剪好的函数，或加载 jsdom 环境包
  return { x_sign: computed };
};
```

运行时用 `node pf_node_bridge.js <模块> <导出名>` 调用，视图从 stdin 传入，结果从 stdout 读出。桥接脚本会把签名模块里的 `console.log` 转到 stderr，避免污染输出。每次签名启动一个 Node 进程，量大时改成 http 签名器，或者在模块内缓存初始化结果后用常驻服务。

R3 补环境的环境包（上游 `templates/env-bundle/` 产物）直接放在 `signers/` 下，由模块 `require`。

### http（R4 浏览器级运行时、R5 页面出值）

签名由外部服务提供：运行时把视图 POST 给 `url_env` 指向的地址，读回 JSON。典型做法是一个常驻 Camoufox 页面加一个本地小服务，在页面里调用原始 SDK 出值。

```yaml
signers:
  page_sign:
    kind: http
    url_env: SHOP_SIGNER_URL
    outputs: [a_bogus]
    route: R5
```

lint 会对 http 签名器给出 `L062` 警告，提醒在交付说明里写清：服务由谁启动、会话谁续期、挂掉时的表现。

## 验证（S1）

签名器写好后，用抓到的真实请求做离线比对：

```bash
pf fixtures spec.yaml captures/x.json --op items --op search -o fixtures/x.private.json
pf verify spec.yaml --fixtures fixtures/x.private.json --record
```

- `pf fixtures` 从抓包里取出每个样本的输入、游标、时间戳、nonce、上游值，以及浏览器实际发出的签名作为期望值。抓包必须是 `include_sensitive=True` 导出的。
- `pf verify` 在临时目录生成一份项目，用固定的输入重建请求，逐字段比较签名输出；不一致时给出**第一个不同字符的位置**和上下文。
- 全部通过时 `--record` 只改写规格里对应签名器的 `verified:` 一行，保留注释和格式。

也可以用 MCP 的 `verify_signer_offline` 验证（适合签名器还在浏览器里调试时），通过后手动在规格里记录：

```yaml
verified: {status: passed, method: verify_signer_offline, samples: captures/x.json#2,3, date: 2026-11-24, scope: "items v3.2.1"}
```

离线全部通过只说明“相同输入下我们算出的值和浏览器一致”（S1）。服务端接不接受，要到 P7 在线验收才知道。离线通过、在线被拒时，回到上游链路 B/E：通常是绑定了会话、环境读值或时序，而不是算法错了。

## 不要做的事

- 不在签名器里发网络请求去“顺便”拿 token，依赖关系应写进 `depends_on`。
- 不缓存签名结果复用到下一个请求。
- 不把密钥、设备指纹原值写进签名器源码再提交；从环境变量或私有配置读取。
- 不为了让 fixtures 通过去改期望值。期望值来自浏览器实际发出的请求，是证据。
