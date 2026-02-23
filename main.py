import asyncio
import base64
import hashlib
import json
import logging
import os
import re
from datetime import datetime
from urllib.parse import unquote

import aiohttp
from aiohttp import ClientSession, TCPConnector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

SS2022_METHODS = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "2022-blake3-chacha8-poly1305"
}

SOURCES = [
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/shadowsockes.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/ss.txt",
    "https://raw.githubusercontent.com/zengfr/free-vpn-subscribe/main/vpn_sub_shadowsocks.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/mahdibland/SS-Collector/master/sub/splitted/ss.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/ermaozi/get_sub/main/sub/ss.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/ss.txt",
]

def safe_base64_decode(content: str) -> str:
    """Base64 decoder فوق‌قوی — سازگار با همه subscriptionهای واقعی"""
    content = content.strip()
    if not content:
        return ""
    content = content.replace("-", "+").replace("_", "/")
    padding = len(content) % 4
    if padding:
        content += "=" * (4 - padding)
    try:
        return base64.b64decode(content).decode("utf-8", errors="ignore")
    except Exception:
        return content

def parse_ss_uri(uri: str) -> dict | None:
    """Parser نهایی و کاملاً ضدگلوله SIP002 + SS2022"""
    if not uri.startswith("ss://"):
        return None
    
    # پاک‌سازی ss:// تو در تو (حتی چند لایه)
    uri = re.sub(r'(ss://)+', 'ss://', uri)
    
    try:
        # حذف tag
        rest = uri[5:].split("#", 1)[0]
        
        if "@" not in rest:
            return None
        
        # rsplit از راست → حتی اگر password حاوی @ باشد هم درست جدا می‌شود
        userinfo_encoded, hostport = rest.rsplit("@", 1)
        
        # مرحله ۱: decode به عنوان base64 (رایج‌ترین حالت)
        userinfo = safe_base64_decode(userinfo_encoded)
        
        # مرحله ۲: اگر : نداشت → خام بوده، unquote کن
        if ":" not in userinfo:
            userinfo = unquote(userinfo_encoded)
        
        if ":" not in userinfo:
            return None
        
        method, password = [x.strip() for x in userinfo.split(":", 1)]
        method_lower = method.lower()
        
        if method_lower not in SS2022_METHODS:
            return None
        
        # host:port
        if ":" not in hostport:
            return None
        host, port_str = hostport.split(":", 1)
        port = int(port_str.split("?")[0].split("/")[0])
        
        if not (1 <= port <= 65535) or len(password) < 16:
            return None
        
        # dedup با SHA-256
        normalized = f"{method_lower}:{password}@{host}:{port}"
        fingerprint = hashlib.sha256(normalized.encode()).hexdigest()
        
        tag = unquote(uri.split("#", 1)[1]) if "#" in uri else "SS2022-Free"
        
        return {
            "method": method,
            "password": password,
            "host": host,
            "port": port,
            "tag": tag,
            "original": uri,
            "fingerprint": fingerprint
        }
    except Exception:
        return None

async def fetch_with_retry(session: ClientSession, url: str, retries: int = 3) -> str:
    for attempt in range(retries):
        try:
            async with session.get(url, timeout=25, headers={"User-Agent": "SS2022-Collector-Ultimate/4.0"}) as resp:
                resp.raise_for_status()
                return await resp.text()
        except Exception as e:
            if attempt == retries - 1:
                logger.warning(f"❌ {url} شکست خورد: {e}")
                return ""
            await asyncio.sleep(1.5 * (attempt + 1))
    return ""

async def main():
    logger.info("🚀 شروع جمع‌آوری Shadowsocks-2022 — نسخه نهایی و ضدگلوله")
    
    connector = TCPConnector(ssl=False, limit=60)
    async with ClientSession(connector=connector) as session:
        tasks = [fetch_with_retry(session, url) for url in SOURCES]
        raw_texts = await asyncio.gather(*tasks)
    
    configs = []
    seen = set()
    
    for text in raw_texts:
        if not text:
            continue
        decoded = safe_base64_decode(text)
        lines = decoded.splitlines() if ":" in decoded or "ss://" in decoded else text.splitlines()
        
        for line in lines:
            line = line.strip()
            if not line.startswith("ss://"):
                continue
            parsed = parse_ss_uri(line)
            if parsed and parsed["fingerprint"] not in seen:
                seen.add(parsed["fingerprint"])
                configs.append(parsed)
    
    logger.info(f"✅ جمع‌آوری نهایی: {len(configs)} کانفیگ SS2022 کاملاً معتبر و منحصربه‌فرد")
    
    if not configs:
        logger.warning("⚠️ هنوز کانفیگ پیدا نشد (رایگان‌ها نادرن). بعداً دوباره اجرا کن.")
        return
    
    os.makedirs("ss2022", exist_ok=True)
    raw_list = [c["original"] for c in configs]
    
    with open("ss2022/ss2022.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(raw_list))
    
    # Subscription برای v2rayNG / Nekobox / HiddifyNG — کاملاً سازگار
    sub_content = "\n".join(raw_list) + "\n"
    sub_b64 = base64.urlsafe_b64encode(sub_content.encode("utf-8")).decode("ascii")
    with open("ss2022/ss2022_sub.txt", "w", encoding="utf-8") as f:
        f.write(sub_b64)
    logger.info("📄 ss2022_sub.txt آماده (کپی مستقیم در v2rayNG — بدون هیچ اروری)")
    
    # Clash Meta
    clash_proxies = [{
        "name": c["tag"],
        "type": "ss",
        "server": c["host"],
        "port": c["port"],
        "cipher": c["method"],
        "password": c["password"],
        "udp": True
    } for c in configs]
    
    with open("ss2022/ss2022_clash.yaml", "w", encoding="utf-8") as f:
        f.write("proxies:\n")
        for p in clash_proxies:
            f.write(f"  - {json.dumps(p, ensure_ascii=False)}\n")
    
    # Sing-box
    sing_outbounds = [{
        "type": "shadowsocks",
        "tag": c["tag"],
        "server": c["host"],
        "server_port": c["port"],
        "method": c["method"],
        "password": c["password"],
        "multiplex": {"enabled": True, "protocol": "smux", "max_connections": 8}
    } for c in configs]
    
    with open("ss2022/ss2022_singbox.json", "w", encoding="utf-8") as f:
        json.dump({"outbounds": sing_outbounds}, f, indent=2, ensure_ascii=False)
    
    logger.info("🎉 تمام! اسکریپت حالا کاملاً بی‌نقص و آماده تولید مداوم است.")
    logger.info("🔗 لینک subscription:")
    logger.info("   https://raw.githubusercontent.com/USERNAME/your-repo/main/ss2022/ss2022_sub.txt")

if __name__ == "__main__":
    asyncio.run(main())
