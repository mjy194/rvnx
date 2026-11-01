# RVNX · Veils Network eXposure

Rust 编写的反向代理 / 内网穿透工具。`clnt` 主动连接 `srv`，将本机 TCP、UDP 服务映射到服务端端口。

```text
访问者 ── TCP / UDP ──> srv 公网映射端口
                         │
                      HTTPS / HTTP/2 隧道
                         │
                       clnt ──> 本地服务
```

当前支持 TCP/UDP 多端口映射、TLS 证书校验、HTTPS 令牌认证、可选 HTTP/2 连接复用、自动重连、心跳、连接数限制和 UDP 空闲会话回收。默认每条 TCP 业务连接新建独立的 TCP/TLS/HTTP/2 连接，只承载该业务的一条 HTTP/2 流，结束后关闭，不进入复用池。每个映射另有独立控制隧道；复用模式下可与其他流共享外层连接。TCP 数据流支持双向传输和半关闭。UDP 保留按映射传输数据报的方式，不为每个数据报或访客新建 TLS 连接。

当前 HTTPS 传输由 v2 引入，与此前直接在 TLS 内传输自定义协议的 v1 不兼容，客户端和服务端需同时升级。静态注册使用 v2，显式策略注册使用 v3，二者共用相同传输与数据帧。现有 TOML 配置仍可解析，但未显式设置 `multiplex = true` 的映射现在默认不复用。`pool_size` 和 `dedicated_pool_size` 不会自动启用复用。

以 Strata／Ollama／vLLM 模型 API 为主、SSH 维护为辅时，参照 [模型 API 与 SSH 配置](docs/strata.md)。默认每条模型或 SSH 的 TCP 连接拥有独立隧道；需要复用时再显式开启，也可以按映射覆盖。

Cloudflare 可选模式提供候选 IP 测速、稳定主备、保活、低速检查和保留旧传输的轮换。配置及接入要求见 [CF 优选与主备](docs/cloudflare.md)，完整样例见 [clnt.cloudflare.toml](examples/clnt.cloudflare.toml) 和 [srv.cloudflare.toml](examples/srv.cloudflare.toml)。仅配置 `[cloudflare]` 时启用此共享模式；普通配置继续默认独立 TLS。

## 可识别性与短连接性能

- 未认证的 HTTP/2 请求得到普通 `404 Not Found`；HTTP/1.1 访问同样返回普通 404。只有校验 HTTPS `Authorization: Bearer` 令牌后才解析隧道协议，未知票据、映射名称、版本等错误不再向未认证访问者暴露。
- 实际协商并使用 HTTP/2，采用标准 POST 请求和双向流式请求/响应正文。认证头设置为敏感字段，不进入 HPACK 动态索引。
- 默认不复用，业务连接之间不共享 TCP 的重传队列。开启复用时，业务连接使用预热的 HTTP/2 连接池，每条池连接最多 128 个并发流。两种模式都将 HTTPS 认证头与首条隧道消息一起发送，减少串行等待。
- HTTP/2 每流接收窗口 256 KiB、连接窗口 32 MiB，只有应用读取数据后才释放流量控制额度。连接窗口覆盖全部允许流的窗口，避免多个停止读取的流耗尽其他流的连接额度。这是窗口上限，并非启动时预分配的内存。
- 心跳改为每次独立随机的 15–25 秒间隔。后端拒绝连接或客户端达到限额时立即撤销待接入票据，避免等待完整建连超时。

这些措施降低直接协议探测和固定行为特征，不保证流量与浏览器不可区分：TLS 指纹、HTTP/2 SETTINGS、SNI、包长和时间分布仍可分析。没有实现浏览器指纹仿真、固定速率发包或包长填充。开发用 localhost 自签证书仅供本机测试。

默认独立连接优先隔离不同业务的丢包和数据通道故障，但每条新业务仍需建立 TCP 和 TLS，首包时延可能高于预热的复用模式。两种模式都保留 HTTPS 和证书校验，也都共享物理带宽与 CPU；控制通道断线仍会释放所属映射的业务连接。当前没有高丢包广域网下的延迟保证，也没有实现 QUIC。

## 本地启动

需要 Rust 工具链、OpenSSL；演示 HTTP 服务和端到端测试还需要 Python 3。以下命令均从仓库根目录执行。

```sh
cargo build --workspace
sh scripts/dev-setup.sh
cargo run -p rvnx-srv -- --config srv.local.toml --check
cargo run -p rvnx-clnt -- --config clnt.local.toml --check
```

开发脚本生成随机令牌、有效期 30 天的 localhost 自签证书和仅监听本机的配置，不覆盖已有文件。分别在三个终端运行：

```sh
# 终端 1：本地 HTTP 服务
python3 -m http.server 8000 --bind 127.0.0.1

# 终端 2：RVNX 服务端
cargo run -p rvnx-srv -- --config srv.local.toml

# 终端 3：RVNX 客户端
cargo run -p rvnx-clnt -- --config clnt.local.toml
```

访问 `http://127.0.0.1:8080` 即可通过 RVNX 访问本地 8000 端口。开发配置同时将服务端 UDP 5353 映射到客户端 UDP 5300；在本机 5300 端口运行 UDP 服务即可使用。TCP 与 UDP 的完整演示可直接运行下方端到端测试。

## 配置和部署

- `srv/`：服务端，生成 `rvnx-srv`。
- `clnt/`：客户端，生成 `rvnx-clnt`。
- `common/`：协议、配置校验与 TLS 传输。
- `examples/`：配置样例。

以 `examples/srv.toml` 和 `examples/clnt.toml` 为模板，将令牌替换为 `openssl rand -hex 32` 的输出，两端保持一致。客户端只能注册服务端已配置的名称和协议，同一个映射只能由一个客户端占用。每个映射独立连接和重连，映射端口在注册时绑定并开始监听，绑定成功后服务端才返回注册确认。

### 服务端多令牌（静态模式）

服务端可将原来的 `token = "..."` 替换为 `tokens` 列表，放在第一个 `[[proxies]]` 之前：

```toml
# 示例占位值，使用前必须替换为不同的随机密钥
tokens = [
    "REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_BYTES",
    "REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_BYTES",
]
```

客户端配置不变：每个客户端仍设置一个 `token`，其值必须在服务端列表中。旧的服务端单 `token` 配置继续有效；`token` 与 `tokens` 必须且只能配置一个。列表不能为空，也不能有重复项；每项与原单令牌要求相同：32–4096 字节，仅可见 ASCII 字符，不能使用示例占位值。

静态模式下所有令牌权限相同，均可访问服务端配置的全部映射及已启用的 CF 测速端点；这不是按令牌隔离用户或端口，同一映射仍只能由一个客户端占用。多令牌认证同时适用于普通 HTTPS、gRPC 隧道和 gRPC 测速。修改或撤销令牌需要重启服务端（现有隧道也会断开）；当前不支持配置热加载。

### 可选：按 token 分配端口策略

**原单 token / 多 tokens 静态配置完全不需要迁移。** 只有希望客户端自主选择公网端口时，才改用显式策略模式：服务端保存每个 token 的完整策略，不再保存该模式的端口映射；客户端保存 `name`、`protocol`、`local`、`remote_port`。

- 服务端参考 [srv.policy.toml](examples/srv.policy.toml)：`[[policies]]` 中配置 token 与 `[policies.policy]` 的 `bind_ip`、`allowed_ports`、`protocols`、`max_mappings`，不能同时配置原顶层 `token` / `tokens` / 静态 `[[proxies]]`。
- 客户端参考 [clnt.policy.toml](examples/clnt.policy.toml)：显式 `policy_mode = true`，每个映射指定准确的 `remote_port`。同样适用于独立 HTTPS、复用和 CF gRPC 模式。
- token 本身就是身份，换 token 就是换身份。客户端认证后自动获取**自己的**策略，仅保留在内存，预校验后请求注册；服务端再次校验并预留配额，绑定成功才确认。
- 同一 token 下映射名称唯一，不同 token 可以同名；同协议、绑定地址的监听端口不可重复，TCP 和 UDP 可以使用相同数字端口。绑定 IP 只能由服务端策略控制。
- `max_mappings` 由服务端按同 token 跨客户端实时计数；本地逐映射校验不安排优先级，超额并发注册的胜出顺序不保证，其他请求明确收到 `quota_exceeded`。
- 拒绝会明确报告映射名称、协议、端口及原因。认证/策略/注册拒绝及确定性畸形协议数据只停止失败映射，不无限重试、不自动换端口，其他映射继续运行。网络断线后重新取策略，仍申请原端口。
- 策略服务端顶层 `connection_wait_secs` 控制 TCP 总建连预算（默认 10 秒）；v3 Open 将剩余毫秒传给客户端，统一覆盖本地 connect、CF 排队和 Attach。Ready 后数据传输不受此预算限制；它是运行参数，不是权限 Policy。
- 目前不做策略实时推送或热加载；修改策略需重启服务端。控制连接结束时释放监听、业务连接和待接入票据。

完整四方时序、逐请求认证、v2/v3 消息字段与示例、二进制/gRPC 封装、状态顺序、错误重试与资源清理见 [通信协议](docs/protocol.md)。

公网部署时，将服务端 `bind` 和映射的 `bind` 设置为所需监听地址，客户端 `server` 指向服务端；使用匹配 `server_name` 的服务端证书，`tls_ca` 指向签发 CA 的 PEM 证书，省略或为空则使用内置公共根证书。自签证书需要安全地复制证书到客户端作为信任锚。服务端私钥仅保留在服务端。路径相对于**启动时的工作目录**解析。

```sh
cargo build --release --workspace
./target/release/rvnx-srv --config /path/to/srv.toml
./target/release/rvnx-clnt --config /path/to/clnt.toml
```

放行服务端控制端口（默认 TCP 7000）及所配置的映射端口。客户端只需要向服务端发起出站 TCP 连接。令牌认证保护隧道注册；映射端口允许网络可达的访问者直接连接，应按需求配置防火墙及被代理服务自身的认证。

| 参数 | 含义 | 默认值 |
| --- | --- | --- |
| `connection_wait_secs` | 从公网 accept 到 Attach Ready 的总建连预算（1–600 秒）；静态模式每映射设置，策略模式服务端顶层设置；CF 可用 120 | 10 |
| `cf_probe_enabled` | 服务端启用带认证的 gRPC 测速端点 | `false` |
| `max_connections` | TCP 并发连接上限 / UDP 访客会话上限，双端各自限制 | 128 |
| `udp_timeout_secs` | UDP 会话空闲时间，服务端每秒清理一次 | 60 |
| `reconnect_secs` | 客户端映射断线后的重试间隔 | 3 |
| `multiplex` | 客户端是否复用 HTTPS 连接；单个映射可覆盖顶层设置 | `false` |
| `pool_size` | 开启复用时的共享池大小（1–32） | 4 |
| `dedicated_pool_size` | 开启复用时，该映射的独享池大小（1–32） | 未设置 |

保持默认独立连接时，可以省略 `multiplex`。显式启用全局复用，在客户端配置的 `[[proxies]]` 之前添加：

```toml
multiplex = true
pool_size = 4
```

若只让模型映射复用，将 `multiplex = true` 与 `dedicated_pool_size = 2` 放在该映射的 `[[proxies]]` 内；SSH 映射可设置 `multiplex = false`。独立模式不创建预热池，仍会校验配置中已有池大小的取值范围。

心跳间隔随机为 15–25 秒，单帧接收超时 60 秒，建连与握手超时 10 秒；服务端最多同时处理 512 条 HTTPS 连接，独立模式下控制与业务连接都计入此限制。控制隧道断开时，对应的数据连接和 UDP 会话会释放，客户端随后重新注册。按 Ctrl+C 停止进程。通过 `RUST_LOG=debug` 可查看详细日志。

UDP 数据报最大 65,507 字节；队列满时丢包。UDP 走可靠 TLS/TCP 流，丢包会导致后续数据报等待重传，适合一般 UDP 转发，实时场景需要评估延迟。首版为端口映射，尚未实现 HTTP 域名路由、QUIC 或配置热加载。

## 验证

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
python3 -m pip install -r tests/requirements.txt
RVNX_LONG_TESTS=1 python3 tests/e2e.py
```

端到端测试使用临时证书、随机本地端口和真实进程，检查 TCP 大数据与半关闭、并发连接、UDP 多访客和空数据报、认证拒绝、映射独占、客户端重连、独立 Python HTTP/2 客户端互通、未认证探测响应、默认独立连接的数量与回收、单条 TLS 故障隔离、可选连接池复用、单条 HTTP/2 连接上的慢流隔离，后端失败快速关闭，以及 CF 模式的认证测速、保留旧传输的主备轮换、硬预算等待和流式 HTTP Keep-Alive。

`RVNX_LONG_TESTS=1` 还会执行 65 秒模型首段等待测试；CI 已启用。异步主备、并发取消、候选回退和配置边界的测试清单及实测覆盖率见 [测试与覆盖率报告](docs/test-coverage.md)。覆盖率可在本地复现：

```sh
rustup component add llvm-tools-preview
python3 scripts/coverage.py
```

该脚本运行全部单元测试和完整端到端测试，分别输出单元测试覆盖率与合并覆盖率，报告位于 `target/coverage/`。构建缓存默认放在系统临时目录，可用 `RVNX_COVERAGE_BUILD_DIR` 指定。

短连接基准（Linux，Python 标准库）：

```sh
cargo build --release --workspace
python3 tests/bench_short.py --samples 1000 --concurrency 1 32 --repeats 3 --output /tmp/rvnx-bench.json
```

基准包含直连与 RVNX 对照，每次请求新建公网侧 TCP 连接，默认发送并接收 1 KiB 数据。报告延迟分位数、完成率及客户端与服务端合计 CPU 时间。结果衡量完整隧道成本，不能当作 TLS 单独开销；回环测试也不能代表公网极限容量。添加 `--multiplex` 可测试复用模式。既有 [性能报告](docs/performance.md) 是之前复用模式的历史结果，不代表当前默认独立 HTTPS 模式。

模型流式首段与 SSH 并行大流量测试见 [最新性能复测（2026-11-01）](docs/performance-2026-11-01.md)，历史数据保留在 [补备优化报告](docs/refill-performance.md) 和 [原始对比报告](docs/streaming-performance.md)。测试比较默认独立 TLS 和本地 CF gRPC 复用实现，包含实际 OpenSSH 回显、固定 200 Mbps 与不限速负载，以及采用 80/112 预算的持续轮换场景。

```sh
python3 tests/bench_streaming.py --seconds 10 --repeats 3 --output /tmp/rvnx-streaming.json
```
