# client

`client` 封装认证、会话、资源解析和 TCP/UDP 连接，供项目内复用。
它不启动代理监听器，也不创建 TUN 或修改系统路由、DNS。

```go
import "geektrust/client"

c, err := client.New(client.Options{
    ControllerURL: controllerURL,
    DeviceID:      deviceID,
    Authenticator: &client.PasskeyAuthenticator{Store: credentials},
    SessionStore:  sessions,
})
if err != nil { return err }
defer c.Close()

if _, err := c.Connect(ctx); err != nil { return err }
conn, err := c.DialContext(ctx, "tcp", address)
if err != nil { return err }
defer conn.Close()
```

- `ControllerURL` 必须是 HTTPS origin（不带路径、查询参数）。`DeviceID` 是持久保存的 32 位大写十六进制标识，可用 `NewDeviceID` 生成。
- `ClientMode` 默认为 false，即 browser 模式；设为 true 后，首次短信验证成功时会尝试绑定授信终端。
- `BlobStore` 收到的是凭据或会话的明文字节，调用方负责保密、原子写入和持久化。同一 passkey 使用同一认证器串行更新计数器；保存失败不会提交断言。
- 认证遵循调用方的 context，允许等待短信输入；网络连接和解析设有超时。连接建立后，用 `SetDeadline` 控制读写。`Close` 会取消操作并关闭自有连接。
- TCP 优先遵循服务端 L3 偏好，否则先尝试流式 TCP；协议不兼容或连接建立失败时可退回 L3，明确的目标拒绝和取消不会触发回退。
- 上海科大保留旧配置的 `app_id` 兜底和网关/DNS 覆盖；其他控制器默认要求资源策略明确授权。
- 默认 TLS 验证 CA。`GatewayTrustStore` 是显式启用的私有证书 TOFU 兜底，正常 CA 验证通过时不强制检查已有 pin；调用方负责持久保存 pin。
- UDP 保留数据报边界，payload 上限为 1372 字节。`ExchangePacket` 仅支持未分片 IPv4 ICMP Echo；实际可用性取决于控制器授权和网关支持。IPv6 目标未实现。
