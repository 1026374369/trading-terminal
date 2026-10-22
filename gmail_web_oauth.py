"""Local Gmail reader for Google Web OAuth credentials; Python standard library only."""

import argparse
import base64
import hashlib
import html
import json
import os
import secrets
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from email.header import decode_header, make_header
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_URL = "https://gmail.googleapis.com/gmail/v1/users/me"
CALLBACK_PATH = "/oauth2callback"


class SetupError(Exception):
    pass


class RemoteError(SetupError):
    def __init__(self, status, code):
        self.status, self.code = status, code
        if code == "invalid_client":
            message = "客户端凭据无效。请检查 client_id 和 client_secret；重置密钥后需更新本地凭据文件。"
        elif code == "invalid_grant":
            message = "Google 授权已失效，请重新运行并授权。"
        elif status == 401:
            message = "令牌被拒绝，请添加 --reauth（PowerShell 使用 -Reauth）重新授权。"
        elif status == 403:
            message = "Google 拒绝访问。请检查 Gmail API 是否启用、账号权限和 Gmail 只读授权。"
        else:
            message = "Google 请求失败（HTTP {}），请稍后重试。".format(status)
        super().__init__(message)


def load_credentials(filename):
    try:
        data = json.loads(Path(filename).read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        raise SetupError("找不到凭据文件：{}。请将下载的 JSON 保存到该位置。".format(filename))
    except (ValueError, UnicodeError):
        raise SetupError("凭据文件不是有效的 UTF-8 JSON。")
    if not isinstance(data, dict):
        raise SetupError("凭据 JSON 顶层必须是对象。")
    client = data.get("web") or data.get("installed")
    if not isinstance(client, dict):
        raise SetupError("凭据必须包含 web 或 installed 对象。")
    for key in ("client_id", "client_secret"):
        if not isinstance(client.get(key), str) or not client[key].strip():
            raise SetupError("凭据缺少有效的 {}。".format(key))
    # A downloaded Web config may omit redirect_uris. Registration is done in Cloud Console.
    return {"client_id": client["client_id"], "client_secret": client["client_secret"]}


def request_json(url, form=None, access_token=None):
    headers = {"Accept": "application/json"}
    body = None
    if form is not None:
        body = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if access_token:
        headers["Authorization"] = "Bearer " + access_token
    request = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        # Never echo Google's raw error body: it can contain request details.
        code = ""
        try:
            body = json.loads(error.read(65536))
            if isinstance(body, dict) and isinstance(body.get("error"), str):
                code = body["error"]
        except (ValueError, OSError):
            pass
        raise RemoteError(error.code, code) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise SetupError("网络连接失败。请确认这台电脑可以访问 Google，并检查网络或代理设置。") from None
    except (ValueError, UnicodeError):
        raise SetupError("Google 返回了无法解析的响应。") from None
    if not isinstance(result, dict):
        raise SetupError("Google 返回的响应格式不正确。")
    return result


class CallbackServer(HTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(3)
        return connection, address


def callback_server(port, state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Authorization codes must not appear in request logs.

        def reply(self, status, message):
            body = message.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            states = params.get("state", [])
            if parsed.path != CALLBACK_PATH:
                self.reply(404, "Not found")
                return
            if len(states) != 1 or not secrets.compare_digest(states[0].encode("utf-8"), state.encode("utf-8")):
                self.reply(400, "授权状态无效。请回到原来的授权页面继续操作。")
                return
            codes, errors = params.get("code", []), params.get("error", [])
            if len(errors) == 1 and not codes:
                self.server.result = {"error": True}
                self.reply(400, "未完成授权。请返回终端查看提示。")
            elif len(codes) == 1 and codes[0] and not errors:
                self.server.result = {"code": codes[0]}
                self.reply(200, "已收到授权回调。请返回 PowerShell 查看连接结果，可以关闭此页面。")
            else:
                self.reply(400, "无效的授权回调。")

    try:
        server = CallbackServer(("127.0.0.1", port), Handler)
    except OSError:
        raise SetupError("无法监听本地端口 {}。请关闭占用该端口的程序，或更换端口并更新 Google 重定向 URI。".format(port)) from None
    server.timeout = 0.5
    server.result = None
    return server


def authorize(client, port, no_browser=False, timeout=300):
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    with callback_server(port, state) as server:
        redirect_uri = "http://127.0.0.1:{}{}".format(server.server_port, CALLBACK_PATH)
        params = {
            "client_id": client["client_id"], "redirect_uri": redirect_uri,
            "response_type": "code", "scope": SCOPE, "state": state,
            "access_type": "offline", "prompt": "consent",
            "code_challenge": challenge, "code_challenge_method": "S256",
        }
        url = AUTH_URL + "?" + urllib.parse.urlencode(params)
        print("请确认 Google Cloud 中的【已获授权的重定向 URI】包含：\n" + redirect_uri)
        print("请在浏览器登录并授权；如未自动打开，复制下面的链接：\n" + url)
        if not no_browser:
            try:
                webbrowser.open(url)
            except webbrowser.Error:
                pass
        deadline = time.monotonic() + timeout
        while server.result is None and time.monotonic() < deadline:
            server.handle_request()
        if server.result is None:
            raise SetupError("等待授权超时。请确认重定向 URI 完全一致，并重新运行脚本。")
        if "error" in server.result:
            raise SetupError("授权未完成。请确认账号已加入测试用户，并在授权页允许 Gmail 只读访问。")
        return request_json(TOKEN_URL, form={
            "client_id": client["client_id"], "client_secret": client["client_secret"],
            "code": server.result["code"], "code_verifier": verifier,
            "grant_type": "authorization_code", "redirect_uri": redirect_uri,
        })


def normalize_token(response, client, previous=None):
    token = dict(previous or {})
    token.update(response)
    if not isinstance(response.get("access_token"), str) or not response["access_token"]:
        raise SetupError("Google 未返回有效的访问令牌。")
    if str(response.get("token_type", "Bearer")).lower() != "bearer":
        raise SetupError("Google 返回了不支持的令牌类型。")
    token["scope"] = response.get("scope", token.get("scope", SCOPE))
    if not isinstance(token["scope"], str) or SCOPE not in token["scope"].split():
        raise SetupError("未获得 Gmail 只读权限。请重新授权并允许该权限。")
    try:
        expires_in = int(response["expires_in"])
        if expires_in <= 0:
            raise ValueError
    except (KeyError, ValueError, TypeError):
        raise SetupError("Google 未返回有效的令牌过期时间。") from None
    # Persist only the fields needed for future API calls; not the client secret.
    return {"client_id": client["client_id"], "access_token": token["access_token"],
            "refresh_token": token.get("refresh_token"), "scope": token["scope"],
            "expires_at": time.time() + expires_in}


def save_token(filename, token):
    filename = Path(filename)
    filename.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".token-", dir=str(filename.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(token, stream, ensure_ascii=False, indent=2)
        os.replace(temporary, str(filename))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def get_token(client, filename, port, reauth=False, no_browser=False):
    cached = {}
    if not reauth:
        try:
            cached = json.loads(Path(filename).read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError, UnicodeError):
            pass
    if (not isinstance(cached, dict) or cached.get("client_id") != client["client_id"]
            or SCOPE not in str(cached.get("scope", "")).split()):
        cached = {}
    expires_at = cached.get("expires_at", 0)
    if (isinstance(expires_at, (int, float)) and expires_at > time.time() + 60
            and isinstance(cached.get("access_token"), str) and cached["access_token"]):
        return cached
    if cached.get("refresh_token"):
        try:
            response = request_json(TOKEN_URL, form={
                "client_id": client["client_id"], "client_secret": client["client_secret"],
                "refresh_token": cached["refresh_token"], "grant_type": "refresh_token",
            })
            token = normalize_token(response, client, cached)
            save_token(filename, token)
            return token
        except RemoteError as error:
            if error.code != "invalid_grant":
                raise
            print("原授权已失效，正在重新授权。")
    token = normalize_token(authorize(client, port, no_browser), client)
    save_token(filename, token)
    if not token.get("refresh_token"):
        print("提示：Google 未返回刷新令牌；访问令牌过期后需要再次授权。")
    return token


def gmail_request(endpoint, token, params=None):
    url = GMAIL_URL + endpoint
    if params:
        url += "?" + urllib.parse.urlencode(params)
    return request_json(url, access_token=token["access_token"])


def safe_text(value):
    value = str(value)
    try:
        value = str(make_header(decode_header(value)))
    except (LookupError, UnicodeError, ValueError):
        pass
    return "".join(character if character.isprintable() else " " for character in value)


def list_messages(token, query, limit):
    listing = gmail_request("/messages", token, {"q": query, "maxResults": limit})
    messages = []
    for item in listing.get("messages", []):
        result = gmail_request("/messages/" + urllib.parse.quote(item["id"], safe=""), token,
                               [("format", "metadata"), ("metadataHeaders", "From"),
                                ("metadataHeaders", "Subject"), ("metadataHeaders", "Date")])
        headers = {header["name"].lower(): header["value"]
                   for header in result.get("payload", {}).get("headers", [])}
        messages.append({"subject": safe_text(headers.get("subject", "（无主题）")),
                         "from": safe_text(headers.get("from", "")),
                         "date": safe_text(headers.get("date", "")),
                         "snippet": safe_text(html.unescape(result.get("snippet", "")))})
    return messages


def main(argv=None):
    parser = argparse.ArgumentParser(description="使用 Google Web OAuth 凭据授权并只读查询 Gmail。")
    parser.add_argument("--credentials", type=Path, default=ROOT / ".private" / "gmail_credentials.json")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--query", default="in:inbox", help="Gmail 搜索条件，例如 newer_than:7d")
    parser.add_argument("--auth-only", action="store_true", help="仅授权并验证 Gmail 连接")
    parser.add_argument("--check-config", action="store_true", help="仅检查本地配置，不联网或打开浏览器")
    parser.add_argument("--reauth", action="store_true", help="重新授权，可用于更换 Gmail 账号")
    parser.add_argument("--no-browser", action="store_true", help="手动复制授权链接到浏览器")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port 必须在 1 到 65535 之间")
    if not 1 <= args.limit <= 50:
        parser.error("limit 必须在 1 到 50 之间")
    try:
        client = load_credentials(args.credentials)
        if args.check_config:
            print("本地凭据格式检查通过（尚未验证 Google Cloud 配置或 Gmail 授权）。")
            print("请在 Google Cloud 注册：http://127.0.0.1:{}{}".format(args.port, CALLBACK_PATH))
            return 0
        token_file = args.credentials.resolve().parent / "gmail_token.json"
        token = get_token(client, token_file, args.port, args.reauth, args.no_browser)
        profile = gmail_request("/profile", token)
        print("Gmail 连接成功：" + safe_text(profile.get("emailAddress", "")))
        if not args.auth_only:
            messages = list_messages(token, args.query, args.limit)
            if not messages:
                print("没有符合搜索条件的邮件。")
            for index, message in enumerate(messages, 1):
                print("\n{}. {}\n   发件人：{}\n   日期：{}\n   摘要：{}".format(
                    index, message["subject"], message["from"], message["date"], message["snippet"]))
        return 0
    except SetupError as error:
        print("错误：" + str(error), file=sys.stderr)
    except OSError:
        print("错误：无法读取或保存本地配置，请检查文件权限和剩余空间。", file=sys.stderr)
    except KeyboardInterrupt:
        print("\n操作已取消。", file=sys.stderr)
    return 1


if __name__ == "__main__":
    for output in (sys.stdout, sys.stderr):
        if hasattr(output, "reconfigure"):
            output.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
