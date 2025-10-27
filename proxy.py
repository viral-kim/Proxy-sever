
# import asyncio
# import aiohttp
# from aiohttp import web
# from aiolimiter import AsyncLimiter
# from dotenv import load_dotenv
# import os
# import base64
# import logging

# # Load environment variables from .env
# load_dotenv()

# # ===========================
# # Configuration
# # ===========================
# PROXY_USERNAME = os.getenv("PROXY_USERNAME", "myproxyuser")
# PROXY_PASSWORD = os.getenv("PROXY_PASSWORD", "mystrongpassword123")
# ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN", "my_super_secure_token_123456789")
# ALLOWED_CLIENT_IPS = os.getenv("ALLOWED_CLIENT_IPS", "127.0.0.1").split(",")
# MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", 100))
# RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", 60))
# LOG_FILE = os.getenv("LOG_FILE", "proxy.log")

# # ===========================
# # Logging Setup
# # ===========================
# logging.basicConfig(
#     filename=LOG_FILE,
#     level=logging.INFO,
#     format="%(asctime)s - %(levelname)s - %(message)s"
# )

# # ===========================
# # Global Settings
# # ===========================
# connection_semaphore = asyncio.Semaphore(MAX_CONNECTIONS)
# rate_limiter = AsyncLimiter(RATE_LIMIT_PER_MINUTE, 60)

# # ===========================
# # Helper Functions
# # ===========================
# def check_auth(headers):
#     """Check basic authentication headers"""
#     auth_header = headers.get("Proxy-Authorization")
#     if not auth_header or not auth_header.startswith("Basic "):
#         return False

#     encoded_credentials = auth_header.split(" ")[1]
#     decoded = base64.b64decode(encoded_credentials).decode("utf-8")
#     username, password = decoded.split(":", 1)

#     return username == PROXY_USERNAME and password == PROXY_PASSWORD

# async def handle_client(reader, writer):
#     """Main proxy handler for incoming connections"""
#     peername = writer.get_extra_info("peername")
#     client_ip = peername[0] if peername else "unknown"

#     if client_ip not in ALLOWED_CLIENT_IPS:
#         writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\nIP not allowed.\r\n")
#         await writer.drain()
#         writer.close()
#         await writer.wait_closed()
#         logging.warning(f"Unauthorized IP attempt: {client_ip}")
#         return

#     try:
#         async with connection_semaphore:
#             request_line = await reader.readline()
#             if not request_line:
#                 return

#             parts = request_line.decode().strip().split()
#             if len(parts) < 3:
#                 return
#             method, url, protocol = parts

#             headers = {}
#             while True:
#                 line = await reader.readline()
#                 if line in (b"\r\n", b""):
#                     break
#                 key, value = line.decode().split(":", 1)
#                 headers[key.strip()] = value.strip()

#             # Check auth
#             if not check_auth(headers):
#                 writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n")
#                 writer.write(b'Proxy-Authenticate: Basic realm="Proxy"\r\n\r\n')
#                 await writer.drain()
#                 writer.close()
#                 await writer.wait_closed()
#                 logging.warning(f"Auth failed for {client_ip}")
#                 return

#             # Handle HTTPS tunneling
#             if method.upper() == "CONNECT":
#                 host, port = url.split(":")
#                 port = int(port)
#                 try:
#                     remote_reader, remote_writer = await asyncio.open_connection(host, port)
#                     writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
#                     await writer.drain()

#                     async def relay(reader1, writer1):
#                         try:
#                             while not reader1.at_eof():
#                                 data = await reader1.read(4096)
#                                 if not data:
#                                     break
#                                 writer1.write(data)
#                                 await writer1.drain()
#                         except Exception:
#                             pass

#                     await asyncio.gather(
#                         relay(reader, remote_writer),
#                         relay(remote_reader, writer)
#                     )

#                 except Exception as e:
#                     logging.error(f"CONNECT failed: {e}")
#                     writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
#                     await writer.drain()
#                 finally:
#                     writer.close()
#                     await writer.wait_closed()
#                 return

#             # Handle normal HTTP
#             async with rate_limiter:
#                 async with aiohttp.ClientSession() as session:
#                     async with session.request(method, url, headers=headers) as resp:
#                         writer.write(
#                             f"HTTP/1.1 {resp.status} {resp.reason}\r\n".encode()
#                         )
#                         for k, v in resp.headers.items():
#                             writer.write(f"{k}: {v}\r\n".encode())
#                         writer.write(b"\r\n")
#                         async for chunk in resp.content.iter_chunked(1024):
#                             writer.write(chunk)
#                         await writer.drain()
#                         logging.info(f"{client_ip} -> {url} [{resp.status}]")

#     except Exception as e:
#         logging.error(f"Error handling {client_ip}: {e}")
#     finally:
#         if not writer.is_closing():
#             writer.close()
#             await writer.wait_closed()


# # ===========================
# # Admin API
# # ===========================
# async def handle_admin(request):
#     token = request.headers.get("Authorization", "")
#     if token != f"Bearer {ADMIN_API_TOKEN}":
#         return web.json_response({"error": "Unauthorized"}, status=401)

#     return web.json_response({
#         "status": "running",
#         "allowed_ips": ALLOWED_CLIENT_IPS,
#         "max_connections": MAX_CONNECTIONS,
#         "rate_limit": RATE_LIMIT_PER_MINUTE
#     })


# # ===========================
# # Main Entry Point
# # ===========================
# async def main():
#     print("Starting proxy and admin API...")

#     # Start proxy server
#     proxy_server = await asyncio.start_server(handle_client, "0.0.0.0", 8888)
#     print("✅ Proxy running on 0.0.0.0:8888")

#     # Start admin API
#     app = web.Application()
#     app.router.add_get("/admin", handle_admin)

#     runner = web.AppRunner(app)
#     await runner.setup()
#     site = web.TCPSite(runner, "127.0.0.1", 8000)
#     await site.start()
#     print("✅ Admin API running on http://127.0.0.1:8000")

#     async with proxy_server:
#         await proxy_server.serve_forever()


# if __name__ == "__main__":
#     print("Starting proxy server.....")
#     try:
#         loop = asyncio.new_event_loop()
#         asyncio.set_event_loop(loop)
#         loop.run_until_complete(main())
#     except KeyboardInterrupt:
#         print("\nShutting down proxy server gracefully...")
#     finally:
#         loop.close()



import asyncio
import os
import aiohttp
from aiohttp import web
from aiolimiter import AsyncLimiter
from dotenv import load_dotenv
import logging

# =========================
# 🔐 Load Environment Variables
# =========================
load_dotenv()

ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN", "default_admin_token")
PROXY_USERNAME = os.getenv("PROXY_USERNAME", "proxyuser")
PROXY_PASSWORD = os.getenv("PROXY_PASSWORD", "proxypass")
ALLOWED_CLIENT_IPS = os.getenv("ALLOWED_CLIENT_IPS", "0.0.0.0").split(",")
MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", 100))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", 60))
LOG_FILE = os.getenv("LOG_FILE", "proxy.log")

# =========================
# 🧾 Setup Logging
# =========================
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# =========================
# ⚙️ Rate Limiter
# =========================
rate_limiter = AsyncLimiter(RATE_LIMIT_PER_MINUTE, 60)

# =========================
# 🌍 Proxy Handler
# =========================
async def handle_client_request(request):
    client_ip = request.remote
    if ALLOWED_CLIENT_IPS != ["0.0.0.0"] and client_ip not in ALLOWED_CLIENT_IPS:
        logging.warning(f"Unauthorized IP: {client_ip}")
        return web.Response(status=403, text="Forbidden: Your IP is not allowed.")

    auth_header = request.headers.get("Proxy-Authorization")
    if not auth_header:
        return web.Response(status=407, text="Proxy Authentication Required")

    try:
        import base64
        method, encoded = auth_header.split(" ")
        username, password = base64.b64decode(encoded).decode().split(":")
    except Exception:
        return web.Response(status=400, text="Invalid authentication header")

    if username != PROXY_USERNAME or password != PROXY_PASSWORD:
        logging.warning(f"Authentication failed from {client_ip}")
        return web.Response(status=403, text="Forbidden: Wrong credentials")

    async with rate_limiter:
        target_url = str(request.url)
        method = request.method
        headers = dict(request.headers)
        body = await request.read()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(method, target_url, headers=headers, data=body) as resp:
                    response_data = await resp.read()
                    return web.Response(body=response_data, status=resp.status, headers=resp.headers)
        except Exception as e:
            logging.error(f"Error fetching {target_url}: {e}")
            return web.Response(status=500, text="Internal Proxy Error")

# =========================
# 🔧 Admin API
# =========================
async def admin_status(request):
    token = request.headers.get("Authorization")
    if token != f"Bearer {ADMIN_API_TOKEN}":
        return web.Response(status=401, text="Unauthorized")

    data = {
        "status": "running",
        "connections": MAX_CONNECTIONS,
        "rate_limit": RATE_LIMIT_PER_MINUTE,
        "allowed_ips": ALLOWED_CLIENT_IPS
    }
    return web.json_response(data)

# =========================
# 🚀 Start Servers
# =========================
async def main():
    proxy_app = web.Application()
    proxy_app.router.add_route('*', '/{path:.*}', handle_client_request)

    admin_app = web.Application()
    admin_app.router.add_get('/status', admin_status)

    proxy_host = "0.0.0.0"
    proxy_port = int(os.getenv("PORT", 8888))  # <-- Important for Railway
    admin_host = "0.0.0.0"
    admin_port = 8000

    print("Starting proxy and admin API...")

    runner_proxy = web.AppRunner(proxy_app)
    await runner_proxy.setup()
    site_proxy = web.TCPSite(runner_proxy, proxy_host, proxy_port)
    await site_proxy.start()

    runner_admin = web.AppRunner(admin_app)
    await runner_admin.setup()
    site_admin = web.TCPSite(runner_admin, admin_host, admin_port)
    await site_admin.start()

    print(f"✅ Proxy running on {proxy_host}:{proxy_port}")
    print(f"✅ Admin API running on http://{admin_host}:{admin_port}")

    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    asyncio.run(main())
