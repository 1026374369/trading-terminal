# Gmail Web OAuth 本地脚本

使用现有 `{"web": {...}}` 类型的 Google OAuth 凭据，在本机打开浏览器完成授权，然后只读查询 Gmail。Python 标准库实现，无需 pip 安装依赖。建议 Python 3.10 或更新版本；兼容 Python 3.8。

## 第一次使用

1. 打开 https://console.cloud.google.com/ ，选择创建该凭据的项目。
2. 在 **API 和服务 → 库** 启用 **Gmail API**。
3. 进入 **Google Auth Platform → Clients（客户端）**，打开现有 Web OAuth 客户端。
4. 在 **已获授权的重定向 URI（Authorized redirect URIs）** 中添加以下完整地址并保存：

   ```text
   http://127.0.0.1:8765/oauth2callback
   ```

   这是重定向 URI 配置。`localhost`、`127.0.0.1`、端口、路径、末尾斜杠都需要与脚本实际地址完全匹配。改动本地 JSON 的 `redirect_uris` 字段不会改变 Google Cloud 配置。

5. 如果应用是 External / Testing，在 **Audience（受众）→ Test users（测试用户）** 添加准备授权的 Gmail 账号。
6. 凭据保存在本目录的 `.private/gmail_credentials.json`。已按本次请求保存所提供的 JSON。因为密钥曾贴到聊天中，建议在控制台重置密钥，并更新此文件中 `web.client_secret` 的值。
7. 在 PowerShell 中运行：

   ```powershell
   Set-Location "E:\workspace\project\noval\gmail-web-oauth"
   .\setup-gmail.ps1
   ```

8. 浏览器打开后，核对应用名称、选择账号并允许 Gmail 只读访问。授权后返回终端，看到“Gmail 连接成功”以及符合条件的最多 10 封收件箱邮件。

如果 PowerShell 提示脚本执行被阻止，可只对本次子进程使用：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\setup-gmail.ps1"
```

此命令不会修改系统执行策略。也可以直接运行：

```powershell
python .\gmail_web_oauth.py
```

## 常用命令

```powershell
# 检查本地凭据格式；不联网，不打开浏览器
.\setup-gmail.ps1 -CheckConfig

# 只完成授权并验证连接，不列出邮件
.\setup-gmail.ps1 -AuthOnly

# 查找最近 7 天的未读收件箱邮件
.\setup-gmail.ps1 -Query "in:inbox is:unread newer_than:7d" -Limit 20

# 重新授权，或更换要读取的 Gmail 账号
.\setup-gmail.ps1 -Reauth

# 8765 端口已被占用时：先在 Google Cloud 注册对应的 8766 地址
.\setup-gmail.ps1 -Port 8766

# 使用其他位置的凭据文件
.\setup-gmail.ps1 -Credentials "C:\你的目录\gmail_credentials.json"
```

完整 Python 参数可通过 `python .\gmail_web_oauth.py --help` 查看。首次授权需要在运行脚本的同一台电脑上打开浏览器。`-NoBrowser` 可手动复制授权链接。

## 令牌和权限

- 只申请 `https://www.googleapis.com/auth/gmail.readonly`。脚本显示发件人、日期、主题和摘要。
- 令牌保存为凭据文件所在目录中的 `gmail_token.json`；以后自动复用和刷新。
- 监听地址固定为本机 `127.0.0.1`，回调验证 OAuth state，并使用 PKCE。
- `.private/` 已加入 Git 忽略。凭据和令牌仍是本地明文文件，请仅留在自己的电脑上；Git 忽略并非加密。
- 用 `-Credentials` 指定其他目录时，需自行保证该目录不会被提交或共享。
- 本脚本是授权与只读查询工具；没有定时任务、交易分析或监控系统集成。

## 常见问题

- **redirect_uri_mismatch**：修改当前客户端的 Authorized redirect URIs，使地址与脚本打印的地址完全一致。首次修改后如尚未生效，可稍后重新运行。
- **403 / access_denied / 仅限测试用户**：检查 OAuth 受众配置、测试用户列表和组织账号策略。
- **Gmail API 被禁用**：在凭据所属项目启用 Gmail API。
- **invalid_client**：检查本地 `client_id` 和 `client_secret` 是否对应同一个客户端；重置后更新本地密钥。
- **授权后来失效**：脚本会在刷新令牌返回 `invalid_grant` 时重新打开授权页。External / Testing 模式且申请 Gmail 权限时，刷新令牌通常在 7 天后失效，长期运行前需根据用途评估生产配置。
- **本地端口被占用**：关闭占用程序，或同时更换脚本端口与控制台回调地址。
- **无法连接 Google**：确保运行脚本和浏览器的电脑可以访问 Google；标准库会使用系统或环境中配置的 HTTP(S) 代理。

## 验证与官方文档

离线验证（模拟授权、令牌刷新和 Gmail 请求，不读取真实邮件）：

```powershell
python -m unittest -v test_gmail_web_oauth.py
```

- [Google Web OAuth 流程与重定向要求](https://developers.google.com/identity/protocols/oauth2/web-server)
- [OAuth 令牌过期和撤销](https://developers.google.com/identity/protocols/oauth2)
- [Gmail 邮件列表接口](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list)
- [Gmail 邮件详情接口](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get)
