import os
import ssl
import socket
import hashlib
import base64
import json
import re
import uuid
import random
import string
import asyncio
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from io import BytesIO

import httpx
import qrcode
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="OSINT & Utility Gateway API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Optional API Keys
IMGBB_KEY = os.getenv("IMGBB_KEY", "")
OCR_SPACE_KEY = os.getenv("OCR_SPACE_KEY", "helloworld")

# ─────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────
async def fetch_json(url: str, timeout: float = 5.0, headers: dict = None):
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        r = await client.get(url, headers=headers or {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            return {"raw_text": r.text}

def success(tool: str, data: dict):
    return JSONResponse({"success": True, "type": tool, "data": data})

def error(tool: str, message: str, status: int = 400):
    return JSONResponse({"success": False, "type": tool, "error": message}, status_code=status)

def require_param(params: dict, key: str, tool: str):
    val = params.get(key)
    if not val:
        raise ValueError(f"Missing required parameter: '{key}'")
    return val

# ─────────────────────────────────────────────
# Documentation Generator (Root Endpoint)
# ─────────────────────────────────────────────
def get_documentation(base_url: str):
    base = str(base_url).rstrip("/")
    endpoints = {
        "network": [
            {"type": "ip", "desc": "IP Geolocation", "example": f"{base}/api?type=ip&ip=8.8.8.8"},
            {"type": "dns", "desc": "DNS Lookup", "example": f"{base}/api?type=dns&domain=github.com&qtype=A"},
            {"type": "whois", "desc": "RDAP/WHOIS", "example": f"{base}/api?type=whois&domain=github.com"},
            {"type": "ssl", "desc": "SSL Expiry", "example": f"{base}/api?type=ssl&domain=google.com"},
            {"type": "ping", "desc": "Port Checker", "example": f"{base}/api?type=ping&host=google.com&port=443"},
            {"type": "headers", "desc": "HTTP Headers", "example": f"{base}/api?type=headers&url=https://github.com"},
            {"type": "mac", "desc": "MAC Address Vendor", "example": f"{base}/api?type=mac&mac=00:1A:2B:3C:4D:5E"}
        ],
        "osint": [
            {"type": "osint_user", "desc": "Multi-site username check", "example": f"{base}/api?type=osint_user&user=torvalds"},
            {"type": "github", "desc": "GitHub Profile Recon", "example": f"{base}/api?type=github&user=torvalds"},
            {"type": "subdomain", "desc": "Fast Subdomain Lookup", "example": f"{base}/api?type=subdomain&domain=yahoo.com"},
            {"type": "email", "desc": "Verify Email & MX", "example": f"{base}/api?type=email&email=test@gmail.com"},
            {"type": "ua", "desc": "User-Agent Parser", "example": f"{base}/api?type=ua&ua=Mozilla/5.0..."}
        ],
        "lookups": [
            {"type": "pincode", "desc": "India Pincode", "example": f"{base}/api?type=pincode&pin=110001"},
            {"type": "ifsc", "desc": "India Bank IFSC", "example": f"{base}/api?type=ifsc&ifsc=SBIN0000001"},
            {"type": "weather", "desc": "Current Weather", "example": f"{base}/api?type=weather&city=London"},
            {"type": "crypto", "desc": "Crypto Prices", "example": f"{base}/api?type=crypto&coin=bitcoin"},
            {"type": "ff", "desc": "Free Fire Player Info", "example": f"{base}/api?type=ff&uid=1633864660&region=IND"}
        ],
        "utilities": [
            {"type": "shorten", "desc": "TinyURL Shortener", "example": f"{base}/api?type=shorten&url=https://google.com"},
            {"type": "qr", "desc": "Generate Base64 QR", "example": f"{base}/api?type=qr&text=hello"},
            {"type": "tts", "desc": "Text to Speech (Audio File)", "example": f"{base}/api?type=tts&text=Hello+World"},
            {"type": "hash", "desc": "MD5/SHA Hash", "example": f"{base}/api?type=hash&text=admin&algo=sha256"},
            {"type": "b64", "desc": "Base64 Encode/Decode", "example": f"{base}/api?type=b64&text=hello&mode=encode"},
            {"type": "urlparse", "desc": "Breakdown URL", "example": f"{base}/api?type=urlparse&url=https://example.com/path?q=1"},
            {"type": "uuid", "desc": "Generate UUIDv4", "example": f"{base}/api?type=uuid"},
            {"type": "passgen", "desc": "Generate Secure Password", "example": f"{base}/api?type=passgen&len=16"},
            {"type": "color", "desc": "Hex to RGB converter", "example": f"{base}/api?type=color&hex=FF5733"}
        ],
        "file_and_data_tools": [
            {"type": "ocr", "desc": "Image OCR (GET via URL or POST file)", "example": f"{base}/api?type=ocr&url=https://i.imgur.com/example.png"},
            {"type": "json_val", "desc": "Validate JSON (GET or POST)", "example": f"{base}/api?type=json_val&json=%7B%22status%22%3A%22ok%22%7D"},
            {"type": "img2url", "desc": "Upload Image -> URL (POST required)", "example": f"POST {base}/api?type=img2url (form-data: file)"}
        ]
    }
    
    total = sum(len(cat) for cat in endpoints.values())
    
    return JSONResponse({
        "status": "online",
        "message": "Welcome to the Unified Utility & OSINT API Gateway",
        "usage": f"Make a GET or POST request to {base}/api?type=<tool_name>",
        "declared_tools_count": total,
        "endpoints": endpoints
    })

@app.get("/")
async def root(request: Request):
    return get_documentation(request.base_url)


# ─────────────────────────────────────────────
# The Mega GET Router
# ─────────────────────────────────────────────
@app.get("/api")
async def api_gateway_get(request: Request):
    params = dict(request.query_params)
    t = params.get("type")

    if not t:
        return get_documentation(request.base_url)

    try:
        # --- NETWORK TOOLS ---
        if t == "ip":
            ip = require_param(params, "ip", t)
            return success(t, await fetch_json(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,as,query"))

        elif t == "dns":
            domain = require_param(params, "domain", t)
            qtype = params.get("qtype", "A")
            data = await fetch_json(f"https://cloudflare-dns.com/dns-query?name={domain}&type={qtype}", headers={"accept": "application/dns-json"})
            return success(t, {"domain": domain, "type": qtype, "answers": data.get("Answer", [])})

        elif t == "whois":
            domain = require_param(params, "domain", t)
            return success(t, await fetch_json(f"https://rdap.org/domain/{domain}"))

        elif t == "ssl":
            domain = require_param(params, "domain", t)
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            return success(t, {"domain": domain, "issuer": dict(x[0] for x in cert.get("issuer", [])), "days_left": (not_after - datetime.utcnow()).days})

        elif t == "ping":
            host = require_param(params, "host", t)
            port = int(params.get("port", 443))
            start = datetime.utcnow()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            result = sock.connect_ex((host, port))
            sock.close()
            return success(t, {"host": host, "port": port, "is_open": result == 0, "ms": int((datetime.utcnow() - start).total_seconds() * 1000)})

        elif t == "headers":
            url = require_param(params, "url", t)
            if not url.startswith("http"): url = "https://" + url
            async with httpx.AsyncClient() as client:
                r = await client.get(url, timeout=5)
            return success(t, {"url": str(r.url), "status": r.status_code, "headers": dict(r.headers)})

        elif t == "mac":
            mac = require_param(params, "mac", t)
            return success(t, await fetch_json(f"https://api.macvendors.com/{mac}"))

        # --- OSINT TOOLS ---
        elif t == "osint_user":
            user = require_param(params, "user", t)
            sites = {
                "github": f"https://api.github.com/users/{user}",
                "reddit": f"https://www.reddit.com/user/{user}/about.json",
                "pinterest": f"https://www.pinterest.com/{user}/",
                "docker": f"https://hub.docker.com/v2/users/{user}/"
            }
            res = {}
            async def check(name, u):
                try:
                    async with httpx.AsyncClient(timeout=3) as c:
                        r = await c.get(u, headers={"User-Agent": "Mozilla/5.0"})
                        res[name] = "Found" if r.status_code == 200 else "Not Found"
                except: res[name] = "Error"
            await asyncio.gather(*[check(n, u) for n, u in sites.items()])
            return success(t, {"username": user, "results": res})

        elif t == "github":
            user = require_param(params, "user", t)
            return success(t, await fetch_json(f"https://api.github.com/users/{user}"))

        elif t == "subdomain":
            domain = require_param(params, "domain", t)
            
            # Fast Provider 1: AlienVault OTX
            try:
                async with httpx.AsyncClient(timeout=3.5) as client:
                    r = await client.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
                    if r.status_code == 200:
                        data = r.json()
                        subs = sorted({item["hostname"].lower() for item in data.get("passive_dns", []) if "hostname" in item and domain in item["hostname"]})
                        if subs:
                            return success(t, {"domain": domain, "count": len(subs), "subdomains": subs[:100], "source": "alienvault"})
            except Exception:
                pass

            # Fast Provider 2: HackerTarget
            try:
                async with httpx.AsyncClient(timeout=3.5) as client:
                    r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
                    if r.status_code == 200 and "error" not in r.text.lower():
                        lines = r.text.strip().split("\n")
                        subs = sorted({line.split(",")[0].lower() for line in lines if "," in line})
                        if subs:
                            return success(t, {"domain": domain, "count": len(subs), "subdomains": subs[:100], "source": "hackertarget"})
            except Exception:
                pass

            return success(t, {"domain": domain, "count": 0, "subdomains": [], "note": "No records found within timeout"})

        elif t == "email":
            email = require_param(params, "email", t)
            domain = email.split("@")[-1]
            mx_data = await fetch_json(f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX", headers={"accept": "application/dns-json"})
            answers = mx_data.get("Answer", [])
            return success(t, {"email": email, "domain_valid": len(answers) > 0, "mx_records_found": len(answers)})

        elif t == "ua":
            ua = require_param(params, "ua", t)
            return success(t, {"user_agent": ua, "is_mobile": any(x in ua.lower() for x in ["mobile", "android", "iphone", "ipad"])})

        # --- PUBLIC LOOKUPS ---
        elif t == "pincode":
            pin = require_param(params, "pin", t)
            return success(t, await fetch_json(f"https://api.postalpincode.in/pincode/{pin}"))

        elif t == "ifsc":
            ifsc = require_param(params, "ifsc", t)
            return success(t, await fetch_json(f"https://ifsc.razorpay.com/{ifsc.upper()}"))

        elif t == "weather":
            city = require_param(params, "city", t)
            geo = await fetch_json(f"https://geocoding-api.open-meteo.com/v1/search?name={city}&count=1")
            if not geo.get("results"): return error(t, "City not found", 444)
            lat, lon = geo["results"][0]["latitude"], geo["results"][0]["longitude"]
            w = await fetch_json(f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current=temperature_2m,wind_speed_10m")
            return success(t, {"city": city, "weather": w.get("current")})

        elif t == "crypto":
            coin = params.get("coin", "bitcoin").lower()
            return success(t, await fetch_json(f"https://api.coingecko.com/api/v3/simple/price?ids={coin}&vs_currencies=usd,inr"))

        elif t == "ff":
            uid = require_param(params, "uid", t)
            region = params.get("region", "IND").upper()
            
            # Robust multi-endpoint fallback
            endpoints = [
                f"https://free-ff-api-src-5plp.onrender.com/api/v1/account?region={region}&uid={uid}",
                f"https://developers.freefirecommunity.com/api/v1/info?region={region.lower()}&uid={uid}"
            ]
            
            for url in endpoints:
                try:
                    async with httpx.AsyncClient(timeout=4.5) as client:
                        r = await client.get(url, headers={"User-Agent": "MyFreeFireApp/1.0"})
                        if r.status_code == 200:
                            return success(t, r.json())
                except Exception:
                    continue

            return error(t, "Free Fire upstream servers are currently unreachable or UID was invalid.", 502)

        # --- UTILITIES ---
        elif t == "shorten":
            url = require_param(params, "url", t)
            async with httpx.AsyncClient() as client:
                r = await client.get(f"https://tinyurl.com/api-create.php?url={url}")
            return success(t, {"original": url, "shortened": r.text})

        elif t == "qr":
            text = require_param(params, "text", t)
            img = qrcode.make(text)
            buf = BytesIO()
            img.save(buf, format="PNG")
            return success(t, {"text": text, "base64": base64.b64encode(buf.getvalue()).decode()})

        elif t == "tts":
            from gtts import gTTS
            text = require_param(params, "text", t)
            buf = BytesIO()
            gTTS(text=text, lang="en").write_to_fp(buf)
            buf.seek(0)
            return StreamingResponse(buf, media_type="audio/mpeg", headers={"Content-Disposition": "inline; filename=tts.mp3"})

        elif t == "hash":
            text = require_param(params, "text", t)
            algo = params.get("algo", "sha256").lower()
            h = hashlib.new(algo)
            h.update(text.encode())
            return success(t, {"algo": algo, "hash": h.hexdigest()})

        elif t == "b64":
            text = require_param(params, "text", t)
            mode = params.get("mode", "encode")
            res = base64.b64encode(text.encode()).decode() if mode == "encode" else base64.b64decode(text.encode()).decode(errors="ignore")
            return success(t, {"mode": mode, "result": res})

        elif t == "urlparse":
            url = require_param(params, "url", t)
            p = urlparse(url if "://" in url else "https://" + url)
            return success(t, {"scheme": p.scheme, "netloc": p.netloc, "path": p.path, "query": parse_qs(p.query)})

        elif t == "uuid":
            return success(t, {"uuid_v4": str(uuid.uuid4())})

        elif t == "passgen":
            length = int(params.get("len", 16))
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            return success(t, {"length": length, "password": "".join(random.choice(chars) for _ in range(length))})

        elif t == "color":
            hex_code = require_param(params, "hex", t).lstrip("#")
            r, g, b = tuple(int(hex_code[i:i+2], 16) for i in (0, 2, 4))
            return success(t, {"hex": f"#{hex_code.upper()}", "rgb": f"rgb({r}, {g}, {b})"})

        # --- GET FALLBACKS FOR POST ENDPOINTS ---
        elif t == "ocr":
            url_param = params.get("url")
            if not url_param:
                return error(t, "OCR via GET requires a 'url' query parameter. To upload an image file directly, send a POST request with multipart/form-data.")
            async with httpx.AsyncClient(timeout=8.0) as client:
                r = await client.post(
                    "https://api.ocr.space/parse/image",
                    data={"apikey": OCR_SPACE_KEY, "url": url_param, "language": "eng"}
                )
            return success(t, {"text": r.json().get("ParsedResults", [{}])[0].get("ParsedText", "").strip()})

        elif t == "json_val":
            json_str = params.get("json")
            if not json_str:
                return error(t, "JSON validation via GET requires a 'json' query parameter. To validate raw payload bodies, send a POST request.")
            try:
                parsed = json.loads(json_str)
                return success(t, {"valid": True, "parsed": parsed, "keys_found": list(parsed.keys()) if isinstance(parsed, dict) else []})
            except Exception as e:
                return error(t, f"Invalid JSON string: {str(e)}")

        elif t == "img2url":
            return error(t, "The 'img2url' tool requires an HTTP POST request with multipart/form-data file payload.")

        else:
            return error("gateway", f"Unknown tool type '{t}'. Access root URL for documentation.", 404)

    except ValueError as ve:
        return error(t, str(ve))
    except Exception as e:
        return error(t, f"Execution failed: {str(e)}", 500)


# ─────────────────────────────────────────────
# The Mega POST Router (For file uploads & raw payloads)
# ─────────────────────────────────────────────
@app.post("/api")
async def api_gateway_post(request: Request, file: UploadFile = File(None)):
    params = dict(request.query_params)
    t = params.get("type")

    if not t:
        return error("gateway", "Missing ?type= parameter in POST request")

    try:
        if t == "img2url":
            if not file or not IMGBB_KEY: return error(t, "Missing file payload or IMGBB_KEY environment variable")
            b64 = base64.b64encode(await file.read()).decode()
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post("https://api.imgbb.com/1/upload", data={"key": IMGBB_KEY, "image": b64})
            return success(t, {"url": r.json()["data"]["url"]})

        elif t == "ocr":
            if not file: return error(t, "Missing file payload")
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(
                    "https://api.ocr.space/parse/image",
                    data={"apikey": OCR_SPACE_KEY, "language": "eng"},
                    files={"file": (file.filename, await file.read())}
                )
            return success(t, {"text": r.json().get("ParsedResults", [{}])[0].get("ParsedText", "").strip()})

        elif t == "json_val":
            body = await request.json()
            return success(t, {"valid": True, "keys_found": list(body.keys()) if isinstance(body, dict) else []})

        else:
            return error("gateway", f"POST method not supported for tool type '{t}'", 405)

    except Exception as e:
        return error(t, f"Execution failed: {str(e)}", 500)
