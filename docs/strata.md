# Strata 模型 API 与 SSH 维护

面向模型 HTTP API 为主、SSH 日常维护为辅的部署。RVNX 透明转发字节，不解析或改写模型请求，不等待完整回答，也不转换 OpenAI、Anthropic 或 Ollama 协议。

已核对的项目为 [Niko1221/Strata](https://github.com/Niko1221/Strata)。这是本地推理服务；官方文档给出的默认地址为 `127.0.0.1:8080`，提供 OpenAI 和 Anthropic 兼容接口。[服务参考](https://github.com/Niko1221/Strata/blob/main/docs/DETAILS.md)、[连接与启动指南](https://github.com/Niko1221/Strata/blob/main/docs/TERMINAL_LAUNCH.md)。

## 连接安排

```text
模型调用端 → HTTPS API 入口 → srv 的 127.0.0.1:18080
                              ║ 每条模型 TCP 连接独立 HTTPS/TLS
                            clnt → Strata 127.0.0.1:8080

维护终端 → srv:2222
             ║ 每条 SSH 连接独立 HTTPS/TLS
           clnt → sshd 127.0.0.1:22
```

使用 [客户端样例](../examples/clnt.strata.toml) 和 [服务端样例](../examples/srv.strata.toml)，填写服务端地址、证书和随机隧道令牌。样例不会覆盖已有 `.local.toml`。

样例显式设置 `multiplex = false`。模型与 SSH 各有一个控制连接；每条业务 TCP 连接另外建立一条独立 HTTPS/TLS 连接，结束后释放。没有空闲预热池，也不会在不同业务连接之间复用隧道。HTTP Keep-Alive 上的多次模型请求仍属于同一条业务 TCP 连接，不会为每个请求重新建隧道。

如果希望某个映射复用，在其 `[[proxies]]` 内添加 `multiplex = true`，再按需设置 `dedicated_pool_size = 2`。只有显式开启复用，池大小才参与连接分配；未配置独享池的复用映射使用顶层共享池。

默认模式隔离业务间的 TCP 丢包和数据通道故障，同时增加每条新业务的握手成本，首包时延可能高于预热池。独立连接不提供网卡带宽或 CPU 的硬隔离；所属控制通道断线仍会释放该映射的业务连接。模型服务的 GPU 排队、首段计算及每秒生成速度由推理服务决定。

`max_connections` 限制的是代理 TCP 连接数，不等于模型并发推理请求数；推理并发和排队需要在 Strata 中配置。

需要走 Cloudflare 优选 IP 时，改用 [CF 配置](cloudflare.md)。这是显式开启的共享主备模式，连接隔离行为与本页默认独立模式不同；模型 API 和 SSH 的服务认证、映射入口配置仍适用。

## 模型 API 入口

模型映射默认仅绑定 srv 本机 `127.0.0.1:18080`，供 HTTPS API 网关转发。调用方到网关、srv 到 clnt 是两个独立的网络区段：隧道 TLS 不会自动把公网映射端口变成 HTTPS，隧道令牌也不是模型 API key。

对外使用时，在 srv 前配置 HTTPS 和模型访问认证，并给 Strata 启用独立 API key。Strata 启动接口提供 `--api-key-env` 等配置；具体启动方式参照上面的官方指南。模型 key 由 RVNX 原样传递，不能替换为 RVNX 隧道令牌。HTTP 网关应关闭流式响应缓冲，并为长提示词首段等待设置足够长的读取超时。

在 srv 本机验证时，OpenAI 兼容调用的 Base URL 为 `http://127.0.0.1:18080/v1`；公网客户端使用你配置的 HTTPS 域名。模型名称以 Strata 实际加载或 `/v1/models` 返回的名称为准。不要把不同客户端的 URL 规则混用：有的要求 `/v1`，有的会自行追加路径。

若换用其他推理服务，只需要把 `local` 改为实际监听地址。Ollama 文档的本地端口为 11434，vLLM 的示例服务端口为 8000；路径和模型字段遵循相应服务。[Ollama 接口](https://docs.ollama.com/api/introduction)、[vLLM 接口](https://docs.vllm.ai/en/stable/serving/online_serving/openai_compatible_server/)。

SSH 通过服务端的 2222 端口连接到模型主机的 sshd，使用 sshd 自身的用户与密钥认证。每条维护连接使用独立的 HTTPS 数据连接。

## 验证边界

使用受控 HTTP 服务测试 SSE 与 NDJSON，验证首段数据在后续生成完成前到达、UTF-8 跨 HTTP chunk 的字节完整性、请求路径及认证头透传，以及同一时段独立维护连接的交互响应。这是传输层测试，不代表已经在本机部署并验证真实 Strata 模型或真实 sshd。

模型数据流没有套用控制心跳的 60 秒接收超时；控制流自行维持心跳。可选长测试模拟 65 秒首段等待：

```sh
cargo build --workspace
python3 -m pip install -r tests/requirements.txt
RVNX_LONG_TESTS=1 python3 tests/e2e.py RVNXTest.test_model_prefill_longer_than_control_timeout
```

完整端到端测试用 `python3 tests/e2e.py`。生产环境还需测真实模型、实际网络 RTT、长会话和同时进行的文件传输；既有短连接性能报告记录的是之前的复用模式，不代表当前默认独立 HTTPS 模式。
