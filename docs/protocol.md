# 隧道协议与策略模式

HTTPS HTTP/2 `POST /api/stream` 和 gRPC `/rvnx.Tunnel/Connect` 均在**每个请求**上验证 `Authorization: Bearer`。一条 HTTP/2 连接可以承载不同令牌的请求；身份不可缓存为连接级身份。启用后的 `/rvnx.Tunnel/Download` 使用相同认证规则。

## 兼容性与模式边界

- **静态模式 v2**：原服务端 `token` 或 `tokens` 加 `[[proxies]]`；原客户端无 `policy_mode`，无 `remote_port`。原配置、注册消息和传输方式不变。
- **策略模式 v3**：服务端仅配置 `[[policies]]`，每项包含令牌和完整策略；与顶层 `token`、`tokens`、静态映射互斥。客户端显式设置 `policy_mode = true`，每个映射配置 `remote_port`。
- 两种模式不得静默降级。策略模式不接受 v2 静态注册，版本不匹配应失败，不能绕过策略。
- token 就是身份；没有额外用户/主体模型。换 token 即换身份。策略响应只包含当前身份的策略，不包含令牌或其他身份。

## 策略注册时序

每个映射使用自己的控制隧道，策略仅保存在进程内存中，不写本地文件：

```text
客户端                                  服务端
HTTPS Bearer + get_policy(version=3)  →  请求级认证，选择该 token 的策略
                                     ←  policy(version=3, policy)
校验 name/protocol/remote_port
register_policy(version=3,
  proxy, protocol, remote_port)       →  独立重校验策略
                                        原子预留名称、端口和身份配额
                                        bind 策略指定 IP + 请求端口
                                     ←  registered(proxy,protocol,remote_port)
                                        或 mapping_error(...,code,reason)
心跳 / TCP Open、Attach / UDP 数据报   ↔  转发
```

策略字段：`bind_ip`（服务端控制，不接受客户端覆盖）、`allowed_ports`（闭区间 `{start,end}` 列表）、`protocols`（`tcp`/`udp`）、`max_mappings`（同一 token 的并发映射上限，含正在绑定的预留）。名称仍须符合原映射名称约束。

服务端无论客户端是否预校验都重新检查。预留覆盖异步 bind 窗口，不能并发绕过配额。只有端口绑定成功后才返回 `registered`；绑定失败、回复失败、任务取消、控制隧道断线均释放预留。一个 token 内名称唯一，不同 token 可以同名。监听端口冲突按协议和服务端绑定地址全局判断，操作系统 bind 仍是最终裁决（包括通配地址重叠）；TCP 与 UDP 可使用同一数字端口。

`max_mappings` 由服务端对同一 token 的所有客户端统一计数；客户端的本地逐项校验不预占配额，也不为映射排序。如果同时请求的映射超过配额，成功顺序取决于实际注册顺序，其余映射收到明确的 `quota_exceeded`，不会替换已成功的映射。

`mapping_error` 总是携带请求的 `proxy`、`protocol`、`remote_port` 和非空 `code`、`reason`。客户端对认证、策略或注册拒绝终止该映射，不反复重试、不悄悄换端口，其他映射继续运行；全部映射终止时客户端非零退出，便于监控发现配置错误。网络断线可以重连；每次都重新取策略并请求原配置端口。

常见拒绝代码：`mode_mismatch`、`policy_denied`、`name_in_use`、`port_in_use`、`quota_exceeded`、`capacity_exhausted`、`bind_failed`。

## TCP 票据与清理

现有 TCP 流程不变：公网连接到达后服务端发送 `open(ticket)`；客户端先连接本地服务，再用新的已认证隧道 `attach(ticket)`；成功后发送 `ready` 并开始双向转发。

票据绑定创建它的 token 和映射实例。Attach 必须先检查所有权再消费票据：其他 token 的尝试不能抢用或销毁票据。控制流上的 `cancel(ticket)` 只可取消同一映射的票据，即便同 token 的其他映射也不可取消。映射退出时关闭监听端口、停止已有转发并撤销待处理票据；旧票据不能被后续同名映射重用。

UDP 沿用控制隧道的 peer ID 和空闲回收机制，不增加每包票据。TCP/UDP 的心跳和流量控制继续生效。策略模式服务端的映射运行参数当前固定使用原默认值：128 条连接/UDP peer、10 秒 TCP 接入等待、60 秒 UDP 空闲回收；客户端仍可设置自己的连接/空闲限制。

## 编码

控制帧沿用 v2 的编码：4 字节网络序长度、1 字节帧类型 `1`、UTF-8 JSON；数据报类型 `2`，后接 8 字节 peer ID 和数据。gRPC 再用现有 Chunk protobuf 消息封装相同字节流。控制 JSON 最大 8192 字节。

新增消息（JSON `type` 为蛇形命名）：

- `get_policy`: `version`
- `policy`: `version`, `policy`
- `register_policy`: `version`, `proxy`, `protocol`, `remote_port`
- `registered`: `proxy`, `protocol`, `remote_port`
- `mapping_error`: `proxy`, `protocol`, `remote_port`, `code`, `reason`

静态模式保留 `register`、`ready`、`error`；两种模式共用 `attach`、`open`、`cancel`、`ping`、`pong`。不提供实时策略推送或热加载；策略变更需重启服务端，客户端重连后重新获取。令牌撤销也需要重启。
