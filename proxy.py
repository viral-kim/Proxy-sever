
import asyncio
import aiohttp
from aiohttp import web
from aiolimiter import AsyncLimiter
from dotenv import load_dotenv
import os
import base64
import logging

# Load environment variables from .env
load_dotenv()

# ===========================
# Configuration
# ===========================
PROXY_USERNAME = os.getenv("PROXY_USERNAME", "myproxyuser")
PROXY_PASSWORD = os.getenv("PROXY_PASSWORD", "mystrongpassword123")
ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN", "my_super_secure_token_123456789")
ALLOWED_CLIENT_IPS = os.getenv("ALLOWED_CLIENT_IPS", "127.0.0.1").split(",")
MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", 100))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", 60))
LOG_FILE = os.getenv("LOG_FILE", "proxy.log")

# ===========================
# Logging Setup
# ===========================
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ===========================
# Global Settings
# ===========================
connection_semaphore = asyncio.Semaphore(MAX_CONNECTIONS)
rate_limiter = AsyncLimiter(RATE_LIMIT_PER_MINUTE, 60)

# ===========================
# Helper Functions
# ===========================
def check_auth(headers):
    """Check basic authentication headers"""
    auth_header = headers.get("Proxy-Authorization")
    if not auth_header or not auth_header.startswith("Basic "):
        return False

    encoded_credentials = auth_header.split(" ")[1]
    decoded = base64.b64decode(encoded_credentials).decode("utf-8")
    username, password = decoded.split(":", 1)

    return username == PROXY_USERNAME and password == PROXY_PASSWORD

async def handle_client(reader, writer):
    """Main proxy handler for incoming connections"""
    peername = writer.get_extra_info("peername")
    client_ip = peername[0] if peername else "unknown"

    if client_ip not in ALLOWED_CLIENT_IPS:
        writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\nIP not allowed.\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        logging.warning(f"Unauthorized IP attempt: {client_ip}")
        return

    try:
        async with connection_semaphore:
            request_line = await reader.readline()
            if not request_line:
                return

            parts = request_line.decode().strip().split()
            if len(parts) < 3:
                return
            method, url, protocol = parts

            headers = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b""):
                    break
                key, value = line.decode().split(":", 1)
                headers[key.strip()] = value.strip()

            # Check auth
            if not check_auth(headers):
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n")
                writer.write(b'Proxy-Authenticate: Basic realm="Proxy"\r\n\r\n')
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                logging.warning(f"Auth failed for {client_ip}")
                return

            # Handle HTTPS tunneling
            if method.upper() == "CONNECT":
                host, port = url.split(":")
                port = int(port)
                try:
                    remote_reader, remote_writer = await asyncio.open_connection(host, port)
                    writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    await writer.drain()

                    async def relay(reader1, writer1):
                        try:
                            while not reader1.at_eof():
                                data = await reader1.read(4096)
                                if not data:
                                    break
                                writer1.write(data)
                                await writer1.drain()
                        except Exception:
                            pass

                    await asyncio.gather(
                        relay(reader, remote_writer),
                        relay(remote_reader, writer)
                    )

                except Exception as e:
                    logging.error(f"CONNECT failed: {e}")
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    await writer.drain()
                finally:
                    writer.close()
                    await writer.wait_closed()
                return

            # Handle normal HTTP
            async with rate_limiter:
                async with aiohttp.ClientSession() as session:
                    async with session.request(method, url, headers=headers) as resp:
                        writer.write(
                            f"HTTP/1.1 {resp.status} {resp.reason}\r\n".encode()
                        )
                        for k, v in resp.headers.items():
                            writer.write(f"{k}: {v}\r\n".encode())
                        writer.write(b"\r\n")
                        async for chunk in resp.content.iter_chunked(1024):
                            writer.write(chunk)
                        await writer.drain()
                        logging.info(f"{client_ip} -> {url} [{resp.status}]")

    except Exception as e:
        logging.error(f"Error handling {client_ip}: {e}")
    finally:
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()


# ===========================
# Admin API
# ===========================
async def handle_admin(request):
    token = request.headers.get("Authorization", "")
    if token != f"Bearer {ADMIN_API_TOKEN}":
        return web.json_response({"error": "Unauthorized"}, status=401)

    return web.json_response({
        "status": "running",
        "allowed_ips": ALLOWED_CLIENT_IPS,
        "max_connections": MAX_CONNECTIONS,
        "rate_limit": RATE_LIMIT_PER_MINUTE
    })


# ===========================
# Main Entry Point
# ===========================
async def main():
    print("Starting proxy and admin API...")

    # Start proxy server
    proxy_server = await asyncio.start_server(handle_client, "0.0.0.0", 8888)
    print("✅ Proxy running on 0.0.0.0:8888")

    # Start admin API
    app = web.Application()
    app.router.add_get("/admin", handle_admin)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 8000)
    await site.start()
    print("✅ Admin API running on http://127.0.0.1:8000")

    async with proxy_server:
        await proxy_server.serve_forever()


if __name__ == "__main__":
    print("Starting proxy server.....")
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        print("\nShutting down proxy server gracefully...")
    finally:
        loop.close()
