# WARP 三出口粘性轮换控制器

用于管理三个 WARP SOCKS5 后端的连接级粘性轮换。控制器通过 sing-box Clash API 原子切换 selector：新连接进入下一个已验证出口，已建立连接继续使用原出口；原出口在连接自然结束后刷新公网 IP，再回到可选池。

固定代理入口：

```text
socks5h://singbox-warp:1081
```

默认出口环：

```text
warp3 → warp4 → warp5
```

## 设计目标

- 消费端始终使用同一个 SOCKS5 地址，不感知后端切换。
- selector 切换只影响新连接，不主动中断已建立连接。
- 每三分钟尝试轮换一次；没有安全可用的候选出口时跳过。
- 候选出口在被选用前通过 IPv6 实时验证 Cloudflare trace 中的 `warp=on`；trace 的 `ip=` 必须是合法 IPv6 地址，IPv4 结果失败关闭。
- 原出口完成 drain 后才在同一容器网络命名空间内原地刷新 WireGuard，不使用固定强杀超时。
- 配置、连接清单、容器身份或依赖存在不确定性时失败关闭。

## 安全不变量

控制器仅在以下条件全部成立时刷新 draining 后端：

1. selector 已切到另一个出口。
2. draining 后端的不可变 Docker container ID 与 container generation 均与进入 drain 时记录一致。
3. IPv4 `iptables` 与 IPv6 `ip6tables` 准入屏障均已安装。
4. Clash `chains` 中该出口的连接数为零。
5. 后端容器内 SOCKS 端口的 `ss state connected` 数量为零。
6. 两套连接清单连续至少两次同时为零。
7. 即将刷新前再次确认 selector、generation、准入屏障和两套连接清单。

准入屏障只拒绝非 loopback 接口进入后端 SOCKS 端口的 TCP `NEW` 连接，不删除 conntrack 状态，也不影响已建立连接。

## 工作流程

1. `tick` 验证 sing-box 配置、Clash selector 和三个后端状态。
2. 按固定环顺序寻找下一个 `ready` 后端。
3. 对当前后端和候选后端执行强制 IPv6 的实时 WARP trace，并从 `singbox-warp` 完成候选后端的真实 SOCKS5 方法协商与 CONNECT 验证；trace 必须返回 `warp=on` 和合法 IPv6 公网地址，候选 IPv6 不得与当前出口重复。
4. 通过 Clash API 切换 selector。
5. 被切出的后端进入 `draining`：
   - 在后端容器内安装 IPv4 和 IPv6 `NEW` 连接准入屏障；
   - 保留已有连接；
   - 统计 Clash chain 和容器内 SOCKS connected 连接。
6. 两套库存连续归零并通过最终复核后，在绑定的 container ID 内执行 `wg-quick down/up`；不重启容器，不重建网络命名空间。
7. 再次确认 IPv4/IPv6 屏障连续存在，验证 `warp=on`、新的 IPv6 公网地址、container ID 与 generation；同时确认容器名仍指向同一实例，然后移除屏障并标记为 `ready`。

当没有 `ready` 后端时，本轮轮换直接跳过。连接连续性优先于固定轮换节拍。

## 环境要求

### 主机

- Linux
- Python 3.11 或更高版本
- Docker Engine 与 Docker CLI
- systemd 247 或更高版本；安装时仍必须使用本机 `systemd-analyze verify` 校验全部指令
- `systemd-analyze`，仅用于安装校验
- OpenSSL，仅用于安装时生成 Clash secret

控制器通过 Docker socket 管理容器。运行账户必须具备 Docker 管理权限；默认 systemd unit 使用 root，但清空 capability 集、关闭私有设备访问、限制 namespace、地址族、系统调用、`/proc` 可见性和可写文件系统。Docker socket 本身仍等价于主机管理权限，因此不得向不可信进程开放。

### sing-box 前端容器

- sing-box 已启用 Clash API。
- 容器内可执行 `cat`、支持 `stat -c %y` 的 `stat`，以及支持普通 connect 模式和 `-w` 的 BusyBox `nc`；不要求 `nc -z`。
- 容器内可执行 `bash`，并支持 `/dev/tcp`、`timeout`、`dd`、`od`、`tr`；控制器用它们从前端完成真实 SOCKS5 方法协商与 CONNECT，而不是只做 TCP 端口连通性检查。
- 配置文件默认位于 `/etc/sing-box/config.json`。
- 容器名固定为 `singbox-warp`。

### WARP 后端容器

三个后端容器必须分别命名为 `warp3`、`warp4`、`warp5`，并在容器内提供：

- 监听 TCP 1081 的 SOCKS5 服务；
- 支持 `--disable` 和 `--noproxy` 的 `curl`；控制器同时清空 `NO_PROXY/no_proxy`，防止 readiness 绕过 SOCKS5；
- 支持 `ss -Hnt state connected '( sport = :1081 )'` 过滤语法的 `ss`；
- 支持 `-w` 锁等待参数的 `iptables` 与 `ip6tables`；
- `wg-quick`、`ip`、`grep`、`mktemp`、`cp`、`chmod` 和 POSIX `sh`；
- `conntrack`、`comment` 和 `REJECT` 规则扩展；
- 安装和删除 INPUT 链规则所需的容器权限。
- `/etc/wireguard/wg0.conf` 不得包含 `PreUp`、`PreDown`、`PostUp` 或 `PostDown` 钩子；匹配忽略大小写和行首空白。控制器先创建权限为 `0600` 的私有配置快照，验证快照后才用同一快照执行原地 down/up。

控制器通过 `docker exec` 在目标后端容器中读取 socket 库存并管理双栈防火墙规则。

## 网络拓扑

`singbox-warp`、`warp3`、`warp4`、`warp5` 必须加入同一个 Docker 网络。默认情况下，控制器要求四个容器只有一个共同网络；若存在多个共同网络，必须显式设置 `WARP_STICKY_NETWORK`。

需要使用固定入口的消费容器也应加入该网络，以便 Docker DNS 将 `singbox-warp` 解析为前端容器。消费端连接字符串保持为：

```text
socks5h://singbox-warp:1081
```

Clash API 必须只监听 `127.0.0.1:9090`，不得绑定共享 Docker 数据网络或发布端口。控制器通过 `docker exec -i singbox-warp nc 127.0.0.1 9090` 在容器网络命名空间内部访问；Bearer secret 与请求正文只通过 stdin 传入，不进入进程参数，也不会经过共享数据网络或环境代理。

控制器严格验证 HTTP/1.0/1.1 状态行、ASCII header 语法和原始 CRLF framing；接受严格匹配的 ASCII `Content-Length`，或单一合法 `Transfer-Encoding: chunked` 并逐块校验十六进制长度、chunk CRLF、终止块与 trailer。拒绝 LF/CR 单独换行、缺少状态码后分隔符、控制字符、重复 header、Content-Length 与 chunked 共存、未知 transfer coding、畸形或截断 chunk、长度不符、截断正文以及 204/205 状态携带的正文；畸形控制响应一律失败关闭。

## sing-box 配置

以下示例给出固定 SOCKS5 入口、三个后端、selector、默认路由和 Clash API 的完整关系：

```json
{
  "inbounds": [
    {
      "type": "socks",
      "tag": "socks-in",
      "listen": "0.0.0.0",
      "listen_port": 1081
    }
  ],
  "outbounds": [
    {
      "type": "selector",
      "tag": "warp-active",
      "outbounds": ["warp3", "warp4", "warp5"],
      "default": "warp3",
      "interrupt_exist_connections": false
    },
    {
      "type": "socks",
      "tag": "warp3",
      "server": "warp3",
      "server_port": 1081,
      "version": "5"
    },
    {
      "type": "socks",
      "tag": "warp4",
      "server": "warp4",
      "server_port": 1081,
      "version": "5"
    },
    {
      "type": "socks",
      "tag": "warp5",
      "server": "warp5",
      "server_port": 1081,
      "version": "5"
    }
  ],
  "route": {
    "final": "warp-active"
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "<strong-random-secret>"
    }
  }
}
```

控制器会同时验证：

- 容器内配置文件仅定义一个名为 `warp-active` 的 selector；
- 配置只允许四个 outbound：`warp-active` 与三个固定后端；selector 的出口顺序严格为 `warp3`、`warp4`、`warp5`，`default` 必须属于该环；
- `interrupt_exist_connections` 明确为 `false`；
- 配置只允许一个 SOCKS inbound，并使用 IPv4 或 IPv6 通配地址监听 `1081`；
- `route.final` 严格为 `warp-active`，`route.rules` 必须缺失或为空；
- 三个后端 outbound 分别严格指向同名容器的 SOCKS5 `1081` 端口；每个对象只允许示例中的固定字段，禁止 `detour`、`network` 或其他可改变实际拨号路径的附加字段；
- Clash API 仅监听容器 loopback `127.0.0.1:9090`，且 secret 与控制器读取的值一致；
- 配置文件修改时间不晚于当前 sing-box 容器启动时间；
- Clash API 运行态返回的 selector 类型正确，且出口列表严格等于三个默认出口。

如果配置文件在容器启动后被修改，必须先安全重启或重建 sing-box 容器，使运行态与配置文件重新一致。

## 安装

在项目根目录执行：

```bash
sudo install -Dm755 warp_sticky_rotate.py \
  /usr/local/bin/warp-sticky-rotate

sudo install -Dm644 README.md \
  /usr/local/share/doc/warp-sticky-rotation/README.md
sudo install -Dm644 LICENSE \
  /usr/local/share/doc/warp-sticky-rotation/LICENSE

sudo install -Dm644 systemd/warp-sticky-rotate.service \
  /etc/systemd/system/warp-sticky-rotate.service
sudo install -Dm644 systemd/warp-sticky-rotate.timer \
  /etc/systemd/system/warp-sticky-rotate.timer
sudo install -Dm644 systemd/warp-sticky-drain-refresh@.service \
  /etc/systemd/system/warp-sticky-drain-refresh@.service

sudo install -d -m0700 \
  /var/lib/warp-sticky-rotate \
  /run/warp-sticky-rotate \
  /etc/warp-sticky-rotation

sudo sh -c 'umask 077; test -s /etc/warp-sticky-rotation/clash.secret || openssl rand -hex 32 > /etc/warp-sticky-rotation/clash.secret'
sudo chmod 0600 /etc/warp-sticky-rotation/clash.secret
```

将 `/etc/warp-sticky-rotation/clash.secret` 的完整内容写入 sing-box 配置的 `experimental.clash_api.secret`，然后安全重启或重建 `singbox-warp`，确保运行态加载了该 secret。完成后继续：

```bash
sudo systemctl daemon-reload
sudo systemd-analyze verify \
  /etc/systemd/system/warp-sticky-rotate.service \
  /etc/systemd/system/warp-sticky-rotate.timer \
  /etc/systemd/system/warp-sticky-drain-refresh@.service
sudo warp-sticky-rotate reconcile
sudo systemctl enable --now warp-sticky-rotate.timer
```

systemd unit 使用 `StateDirectory=warp-sticky-rotate` 和 `RuntimeDirectory=warp-sticky-rotate` 创建权限为 `0700` 的状态及锁目录，使用 `UMask=0077`，并启用 capability、设备、namespace、地址族、系统调用和 `/proc` 限制。

## 配置

生产拓扑是固定安全边界，不支持通过环境变量覆盖：

- 前端容器：`singbox-warp`
- 固定入口：IPv4 或 IPv6 通配地址的 `1081`
- selector：`warp-active`
- 出口环：`warp3`、`warp4`、`warp5`
- 后端 SOCKS5 端口：`1081`
- Clash API 端口：`9090`

可调运行参数如下。tick service 和 drain worker 必须使用一致配置。

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `WARP_STICKY_SINGBOX_CONFIG` | `/etc/sing-box/config.json` | sing-box 容器内配置文件路径 |
| `WARP_STICKY_NETWORK` | 自动检测 | 四个容器唯一共享的 Docker 网络 |
| `WARP_STICKY_CLASH_SECRET_FILE` | `/etc/warp-sticky-rotation/clash.secret` | Clash API secret 文件；必须为当前运行用户所有的非符号链接普通文件，权限严格为 `0600`，内容非空；secret 值本身不支持环境变量覆盖 |
| `WARP_STICKY_TRACE_URL` | `https://www.cloudflare.com/cdn-cgi/trace` | WARP 验证地址，必须使用 HTTPS |
| `WARP_STICKY_STATE` | `/var/lib/warp-sticky-rotate/state.json` | 状态文件 |
| `WARP_STICKY_LOCK` | `/run/warp-sticky-rotate/controller.lock` | 全局控制器锁 |
| `WARP_STICKY_DRAIN_LOCK_DIR` | `/run/warp-sticky-rotate` | 后端 worker 锁目录 |
| `WARP_STICKY_DRAIN_POLL_S` | `1` | drain 采样间隔，秒 |
| `WARP_STICKY_DRAIN_ZERO_SAMPLES` | `2` | refresh 前连续零样本数，最小为 2 |
| `WARP_STICKY_REFRESH_ATTEMPTS` | `3` | 最大刷新尝试次数 |
| `WARP_STICKY_REFRESH_POLL_S` | `1` | readiness 轮询间隔，秒 |
| `WARP_STICKY_REFRESH_READY_TIMEOUT_S` | `120` | 单次 readiness 超时，秒 |
| `WARP_STICKY_FAILED_RETRY_S` | `180` | failed 状态最小重试间隔；到期后重新解析容器名称和 generation、重装屏障并执行实时 WARP 探测，不复用旧 drain identity |


如需为两个 service 提供同一组可调环境参数，可创建权限为 `0600` 的 `/etc/warp-sticky-rotation/controller.env`，并为以下 unit 创建包含 `EnvironmentFile=/etc/warp-sticky-rotation/controller.env` 的 drop-in：

```text
warp-sticky-rotate.service
warp-sticky-drain-refresh@.service
```

程序只读取自身进程环境，不会自动加载 `controller.env`。直接执行 `warp-sticky-rotate reconcile|tick|status|drain-refresh` 时，必须与 service 使用同一组环境变量；若使用了定制 state、lock 或其他路径，请通过 `EnvironmentFile` 对应的 shell 导出，或优先使用 systemd unit：

```bash
# 推荐：通过 service 执行 tick（自动加载 drop-in 环境）
sudo systemctl start warp-sticky-rotate.service

# 需要直接 CLI 时，由 root shell 读取 0600 环境文件并执行：
sudo sh -c 'set -a; . /etc/warp-sticky-rotation/controller.env; set +a; exec /usr/local/bin/warp-sticky-rotate reconcile'
```

安全应用环境参数：

```bash
set -euo pipefail
sudo systemctl stop warp-sticky-rotate.timer
sudo systemctl stop warp-sticky-rotate.service
sudo systemctl daemon-reload
for tag in warp3 warp4 warp5; do
  unit="warp-sticky-drain-refresh@${tag}.service"
  if systemctl is-active --quiet "$unit"; then
    sudo systemctl restart "$unit"
  fi
done
# 使用与 service 相同的环境；若存在 controller.env，先加载再执行 CLI
if [ -f /etc/warp-sticky-rotation/controller.env ]; then
  sudo sh -c 'set -a; . /etc/warp-sticky-rotation/controller.env; set +a; exec /usr/local/bin/warp-sticky-rotate reconcile'
else
  sudo warp-sticky-rotate reconcile
fi
sudo systemctl enable --now warp-sticky-rotate.timer
```

`set -euo pipefail` 保证任一 stop、restart、`reconcile` 或启用步骤失败时立即终止，不会继续重新启用 timer。重启 drain worker 不会主动关闭后端已有连接；准入屏障和本地状态会由新进程继续复核。修改固定拓扑或 Clash secret 需要重启 `singbox-warp`，会中断其现有连接，因此必须安排维护窗口，而不能作为常规在线配置操作。

## 命令

若已配置 `controller.env` drop-in，下列直接 CLI 命令必须由 root shell 加载同一环境后执行，例如 `sudo sh -c 'set -a; . /etc/warp-sticky-rotation/controller.env; set +a; exec /usr/local/bin/warp-sticky-rotate status'`；也可以改用对应 systemd unit。默认路径下可直接执行。

### 对齐状态

读取并验证 selector、配置文件和容器状态，修复本地状态文件，不主动切换出口：

```bash
sudo warp-sticky-rotate reconcile
```

### 执行一次轮换

```bash
sudo systemctl start warp-sticky-rotate.service
# 或：
sudo warp-sticky-rotate tick
```

### 启动指定后端的 drain/refresh

通常由 systemd 自动调用：

```bash
sudo systemctl start warp-sticky-drain-refresh@warp3.service
# 或：
sudo warp-sticky-rotate drain-refresh warp3
```

### 查看状态

```bash
sudo warp-sticky-rotate status
```

输出为 JSON，包含当前 selector、三个后端的 phase、IP、container ID、container generation、两套连接库存、最近一次切换耗时和 drain/refresh 状态。

状态文件和 journal 会保存 WARP 公网出口 IP，属于需要按运维日志策略保护的元数据。

## 状态机

```text
unknown → ready → active → draining → refreshing → ready
                                         └──────→ failed
```

- `unknown`：状态尚未确认或关键 generation 缺失。
- `ready`：实时 WARP 验证通过后可被 selector 选用。
- `active`：当前承载新连接。
- `draining`：双栈屏障已启用，等待存量连接结束。
- `refreshing`：正在刷新并验证公网出口。
- `failed`：刷新、身份或依赖检查失败；清除旧 drain identity，并在能够定位当前实例时保持或重装准入屏障。达到重试时间后以当前名称映射重新绑定 immutable ID/generation，实时探测成功后才恢复为 `ready`。

状态文件：

```text
/var/lib/warp-sticky-rotate/state.json
```

全局锁：

```text
/run/warp-sticky-rotate/controller.lock
```

## systemd

定时器每三分钟尝试轮换一次：

```bash
systemctl status warp-sticky-rotate.timer
systemctl list-timers warp-sticky-rotate.timer
```

查看日志：

```bash
journalctl -u warp-sticky-rotate.service \
  -u 'warp-sticky-drain-refresh@*.service'
```

停止自动轮换：

```bash
sudo systemctl stop warp-sticky-rotate.timer
```

停止定时器不会关闭 WARP 容器，也不会修改当前 selector。已经启动的 drain worker 会继续遵守连接库存与最终复核门禁。

## 验证

运行测试和静态检查：

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile warp_sticky_rotate.py tests/test_warp_sticky_rotate.py
ruff check warp_sticky_rotate.py tests
systemd-analyze verify \
  systemd/warp-sticky-rotate.service \
  systemd/warp-sticky-rotate.timer \
  systemd/warp-sticky-drain-refresh@.service
```

从能够解析 `singbox-warp` 的同一 Docker 网络检查固定入口：

```bash
curl --proxy socks5h://singbox-warp:1081 \
  https://www.cloudflare.com/cdn-cgi/trace
```

预期包含：

```text
warp=on
```

检查控制器状态：

```bash
sudo warp-sticky-rotate status
```

任何依赖、配置或运行态不满足门禁时，命令应返回非零状态或输出 JSON `error`，不得继续 selector 切换或后端刷新。

## 运行约束

- 不要通过其他脚本或人工 Clash API PUT 修改同一个 selector。
- 不要删除控制器创建的 IPv4 或 IPv6 准入屏障。
- 不要将同一后端加入多个独立轮换控制器。
- 在任一后端处于 `draining` 或 `refreshing` 时，禁止对该后端执行 `docker restart`、停止、重建、删除、重命名或同名替换。外部容器生命周期操作会改变 generation 或网络命名空间，并可能销毁容器内准入屏障；这是不可与刷新并发的硬性运维前提。控制器检测到身份变化时会失败关闭、为当前实例重装屏障，并在 cooldown 后用新身份重新探测，但该检测不能把未经协调的外部重启变成安全操作。
- `interrupt_exist_connections` 必须保持为 `false`。
- sing-box selector 的运行态出口列表必须严格等于 `warp3`、`warp4`、`warp5`。
- 未完成 TCP 建连的请求可能在后端进入 draining 时被拒绝；调用方应具备正常的连接重试能力。
- 没有安全可用出口时宁可跳过本轮，不强制回收长连接。

## 项目结构

```text
.
├── .gitignore
├── LICENSE
├── README.md
├── warp_sticky_rotate.py
├── systemd/
│   ├── warp-sticky-rotate.service
│   ├── warp-sticky-rotate.timer
│   └── warp-sticky-drain-refresh@.service
└── tests/
    └── test_warp_sticky_rotate.py
```

## 许可证

本项目使用 [MIT License](LICENSE)。
