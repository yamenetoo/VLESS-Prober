import base64
import os
import re
import socket
import ssl
import sys
import urllib.parse
from typing import Dict, List, Optional, Tuple
from telegram import Bot
import asyncio

# Get credentials from environment variables
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "-1003051753052")
SUB_URL = os.getenv("SUBSCRIPTION_URL", "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/refs/heads/main/final.txt")
TIMEOUT = int(os.getenv("TIMEOUT", "8"))

def fetch_text(url: str) -> str:
    import urllib.request
    with urllib.request.urlopen(url, timeout=20) as resp:
        return resp.read().decode("utf-8", errors="replace")

def parse_vless_uri(uri: str) -> Optional[Dict]:
    if not uri.lower().startswith("vless://"):
        return None
    try:
        u = urllib.parse.urlsplit(uri)
        userinfo, hostport = None, u.netloc
        if "@" in u.netloc:
            userinfo, hostport = u.netloc.split("@", 1)
        uuid = userinfo or ""
        host, port = hostport, None
        if ":" in hostport and not hostport.endswith("]"):
            h, p = hostport.rsplit(":", 1)
            if p.isdigit():
                host, port = h, int(p)
        q = dict(urllib.parse.parse_qsl(u.query))
        net = q.get("type", q.get("network", "tcp")).lower()
        sec = q.get("security", "none").lower()
        sni = q.get("sni") or q.get("peer") or q.get("host") or host
        host_header = q.get("host") or q.get("authority") or host
        path = q.get("path", "/")
        alpn = q.get("alpn", "")
        alpn_list = [a.strip() for a in alpn.split(",") if a.strip()] if alpn else []
        name = urllib.parse.unquote(u.fragment or "")
        return {
            "raw": uri.strip(),
            "uuid": uuid,
            "host": host,
            "port": port or (443 if sec in ("tls","reality") or net in ("ws","grpc") else 80),
            "network": net,
            "security": sec,
            "sni": sni,
            "host_header": host_header,
            "path": path if path.startswith("/") else "/" + path,
            "alpn": alpn_list,
            "name": name,
        }
    except Exception:
        return None

def extract_vless_links(text: str) -> List[str]:
    return re.findall(r"vless://[^\s]+", text, flags=re.IGNORECASE)

def tcp_connect(host: str, port: int) -> Tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True, "tcp_ok"
    except Exception as e:
        return False, f"tcp_err:{type(e).__name__}"

def tls_handshake(host: str, port: int, sni: Optional[str], alpn: List[str]) -> Tuple[bool, str]:
    ctx = ssl.create_default_context()
    if alpn:
        try:
            ctx.set_alpn_protocols(alpn)
        except Exception:
            pass
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=(sni or host), do_handshake_on_connect=True) as ssock:
                proto = ssock.selected_alpn_protocol() or ""
                return True, "tls_ok" + (f"/alpn:{proto}" if proto else "")
    except ssl.SSLError as e:
        return False, f"tls_sslerr:{e.reason if hasattr(e,'reason') else 'SSLError'}"
    except Exception as e:
        return False, f"tls_err:{type(e).__name__}"

def ws_upgrade(host: str, port: int, secure: bool, sni: Optional[str], host_header: str, path: str) -> Tuple[bool, str]:
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("utf-8")
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            if secure:
                ctx = ssl.create_default_context()
                if sni:
                    ssock = ctx.wrap_socket(sock, server_hostname=sni)
                else:
                    ssock = ctx.wrap_socket(sock, server_hostname=host)
                sock = ssock
            sock.sendall(req)
            resp = sock.recv(1024)
            if b" 101 " in resp and b"Switching Protocols" in resp:
                return True, "ws_101"
            return False, f"ws_bad_resp:{resp[:64]!r}"
    except ssl.SSLError as e:
        return False, f"ws_tls_sslerr:{e.reason if hasattr(e,'reason') else 'SSLError'}"
    except Exception as e:
        return False, f"ws_err:{type(e).__name__}"

def probe_node(n: Dict) -> Dict:
    host, port = n["host"], n["port"]
    result = {"name": n["name"], "host": host, "port": port, "network": n["network"], "security": n["security"], "status": "fail", "detail": ""}
    if not host or len(host) > 253:
        result["detail"] = "invalid_host"
        return result

    net = n["network"]
    sec = n["security"]

    if sec == "reality":
        result["status"] = "unknown"
        result["detail"] = "reality_unprobed"
        return result

    if net == "grpc":
        ok, det = tls_handshake(host, port, n["sni"], n["alpn"] or ["h2"])
        result["status"] = "ok" if ok else "fail"
        result["detail"] = det
        return result

    if net == "ws":
        secure = (sec == "tls")
        ok, det = ws_upgrade(host, port, secure, n["sni"], n["host_header"], n["path"])
        if not ok and secure:
            ok2, det2 = tls_handshake(host, port, n["sni"], n["alpn"])
            if ok2:
                result["status"] = "ok"
                result["detail"] = f"{det}|fallback:{det2}"
                return result
        result["status"] = "ok" if ok else "fail"
        result["detail"] = det
        return result

    if sec == "tls":
        ok, det = tls_handshake(host, port, n["sni"], n["alpn"])
    else:
        ok, det = tcp_connect(host, port)

    result["status"] = "ok" if ok else "fail"
    result["detail"] = det
    return result

async def send_telegram_message(message: str):
    if not TELEGRAM_BOT_TOKEN:
        print("TELEGRAM_BOT_TOKEN not set, skipping Telegram message")
        return
        
    try:
        bot = Bot(token=TELEGRAM_BOT_TOKEN)
        await bot.send_message(chat_id=CHAT_ID, text=message, parse_mode="Markdown")
        print(f"✓ Successfully sent message to Telegram")
    except Exception as e:
        print(f"✗ Failed to send Telegram message: {e}")

async def main():
    # Validate environment variables
    if not TELEGRAM_BOT_TOKEN:
        print("Warning: TELEGRAM_BOT_TOKEN environment variable not set")
    
    # Validate SUBSCRIPTION_URL
    if not SUB_URL or SUB_URL.strip() == "":
        print("Error: SUBSCRIPTION_URL environment variable is not set or empty")
        sys.exit(1)
    
    try:
        print(f"Fetching subscription from: {SUB_URL}")
        text = fetch_text(SUB_URL)
        print("✓ Successfully fetched subscription data")
    except Exception as e:
        error_msg = f"Failed to fetch subscription from {SUB_URL}: {e}"
        print(error_msg)
        # Try to send error to Telegram if token is available
        if TELEGRAM_BOT_TOKEN:
            await send_telegram_message(f"❌ {error_msg}")
        sys.exit(1)

    links = extract_vless_links(text)
    nodes = [parse_vless_uri(u) for u in links]
    nodes = [n for n in nodes if n]

    if not nodes:
        message = "No VLESS links found in the subscription."
        print(message)
        if TELEGRAM_BOT_TOKEN:
            await send_telegram_message(message)
        return

    print(f"Found {len(nodes)} VLESS nodes. Probing (timeout {TIMEOUT}s each)...\n")
    
    working_servers = []
    
    for n in nodes:
        result = probe_node(n)
        if result["status"] == "ok":
            working_servers.append(n["raw"])
            print(f"✓ Working server: {n['name'] or n['host']}")
        else:
            print(f"✗ Failed server: {n['name'] or n['host']} - {result['detail']}")

    # Send all working servers to Telegram
    if working_servers:
        message = "✅ *Working VLESS Servers:*\n\n" + "\n".join(working_servers)
        # Limit message length to avoid Telegram's 4096 character limit
        if len(message) > 4000:
            message = message[:4000] + "\n\n... (truncated due to length)"
        
        await send_telegram_message(message)
        print(f"\n✓ Sent {len(working_servers)} working servers to Telegram")
    else:
        message = "❌ No working VLESS servers found in this check."
        await send_telegram_message(message)
        print(f"\n✗ No working servers found to send")

if __name__ == "__main__":
    asyncio.run(main())
