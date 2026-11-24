# 传输指纹（P5）

curl_cffi 用 `impersonate` 模拟某个浏览器的 TLS ClientHello、HTTP/2 设置和默认请求头。服务端看到的“这是什么浏览器”，来自三处：TLS/H2 指纹、User-Agent、Client Hints 等请求头。**三处必须讲同一个故事**，否则自己制造了一个最容易被识别的异常。

## 规则

| 检查 | 级别 | 说明 |
|---|---|---|
| `FP001` 目标不存在 | error | 已安装的 curl_cffi 不提供这个 impersonate 值。`pf targets` 查看可用值 |
| `FP003` 族不一致 | error | 例如 UA 是 Firefox，impersonate 是 chrome131 |
| `FP004` 版本差距大 | warning | UA 主版本与目标相差超过 6；选最接近的版本 |
| `FP005` 平台不一致 | warning | 移动端 UA 配桌面目标，或反过来 |
| `FP006` 跨族请求头 | error | Firefox/Safari 的 UA 却带了 `sec-ch-ua*`（只有 Chromium 发） |
| `FP007` UA 写在请求头 | warning | UA 只放 `transport.user_agent`，避免两处不同步 |
| `FP008` 与抓包 UA 不同 | error/warning | 签名或风控可能绑定 UA；换族是 error |

```bash
pf fp-check spec.yaml --capture captures/x.json
```

## Camoufox 抓的包用什么目标

Camoufox 基于 Firefox，抓到的 UA 一般是 Firefox。生成代码时：

- 默认保持 Firefox UA，并选择最接近的 `firefoxNNN` 目标（`pf import` 已自动选好）。
- 想改用 Chrome 指纹时，UA、Client Hints（`sec-ch-ua` 系列）和请求头顺序都要换成 Chrome 的。而且签名或风控如果在页面里读过 UA，签名本身也可能要重新取样。不要只改 `impersonate` 一项。

## 现象与排查

传输层问题的定位方法在上游 hello-js-reverse-skill 的链路 C（“浏览器能过，本地同样的头不过”）。本 Skill 只负责让生成代码不犯低级错误。排查前先排除：

1. 用过的一次性值（nonce、签名）被重放；
2. 会话不同（Cookie 没带上，或换了 IP 后会话失效）；
3. 业务码其实指向参数问题，不是指纹问题。

都排除后，再做传输对照：同一请求分别用不同 `impersonate` 目标发送，只改这一个变量，按结果分类记录。

## 代理与会话

- 代理地址写在 `proxy_env` 指向的环境变量里，不写进规格。
- 换代理出口时会话可能失效，依赖接口要重新执行；生成的 Scrapy 项目不复用跨代理的 TLS 会话缓存（scrapy-impersonate 的默认行为）。
- 频率限制、验证页、账号受限（上游链路 K）出现时，停止当批，不靠换身份继续。

## 请求头

- `default_headers` 只放所有接口都需要、且与浏览器一致的头（Accept、Accept-Language、Origin、Referer）。
- 自定义头（`X-*`）放在各接口的 `headers` 里，按上游删减实验的结论保留必要的。
- curl_cffi 会为所选目标补齐浏览器默认头；规格里写的同名头会覆盖它们。
