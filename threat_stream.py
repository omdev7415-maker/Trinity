import asyncio
import httpx
import random
import socket
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ThreatStream")

# In-memory cache to stay under GeoIP limits
_geoip_cache = {}

# Keep a rotating spool of live attacks
live_attacks_spool = []

# Abuse.ch recent URLs CSV
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

# Free GeoIP
GEO_IP_URL = "http://ip-api.com/json/"

# Top target coordinates to simulate realistic distribution of global targets
POTENTIAL_TARGETS = [
    {"name": "Washington, DC", "lat": 38.8951, "long": -77.0364, "country": "US"},
    {"name": "London, UK", "lat": 51.5074, "long": -0.1278, "country": "GB"},
    {"name": "Frankfurt, DE", "lat": 50.1109, "long": 8.6821, "country": "DE"},
    {"name": "Tokyo, JP", "lat": 35.6762, "long": 139.6503, "country": "JP"},
    {"name": "Sydney, AU", "lat": -33.8688, "long": 151.2093, "country": "AU"},
    {"name": "Singapore", "lat": 1.3521, "long": 103.8198, "country": "SG"},
    {"name": "Local Data Center", "lat": 37.7749, "long": -122.4194, "country": "US"} # SF
]

def resolve_domain(domain):
    try:
        if ':' in domain:
            domain = domain.split(':')[0]
        return socket.gethostbyname(domain)
    except Exception:
        return None

async def fetch_geo(ip, client):
    if not ip:
        return {"lat": random.uniform(-60, 60), "lon": random.uniform(-180, 180), "country": "Unknown", "city": "Unknown"}
    if ip in _geoip_cache:
        return _geoip_cache[ip]
    
    try:
        res = await client.get(f"{GEO_IP_URL}{ip}", timeout=5)
        if res.status_code == 200:
            data = res.json()
            if data.get('status') == 'success':
                geo = {"lat": data['lat'], "lon": data['lon'], "country": data['country'], "city": data['city']}
                _geoip_cache[ip] = geo
                return geo
        # Fallback if rate limited or invalid
        geo = {"lat": random.uniform(-60, 60), "lon": random.uniform(-180, 180), "country": "Unknown", "city": "Unknown"}
        _geoip_cache[ip] = geo
        return geo
    except Exception:
        return {"lat": random.uniform(-60, 60), "lon": random.uniform(-180, 180), "country": "Unknown", "city": "Unknown"}

async def ingest_threats():
    global live_attacks_spool
    logger.info("Threat ingest daemon starting...")
    
    import xml.etree.ElementTree as ET

    async with httpx.AsyncClient() as client:
        while True:
            try:
                news_items = []
                try:
                    logger.info("Fetching cyber news from The Hacker News...")
                    res_news = await client.get("https://feeds.feedburner.com/TheHackersNews", headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
                    if res_news.status_code == 200:
                        root = ET.fromstring(res_news.text)
                        for item in root.findall('.//item')[:15]:
                            title = item.find('title')
                            enclosure = item.find('enclosure')
                            img_url = enclosure.get('url') if enclosure is not None else ""
                            if title is not None and title.text:
                                news_items.append({"title": title.text, "image": img_url})
                except Exception as e:
                    logger.error(f"Error fetching news: {e}")

                logger.info("Fetching latest threats from Abuse.ch...")
                res = await client.get(URLHAUS_CSV_URL, timeout=15)
                if res.status_code == 200:
                    lines = res.text.split('\n')
                    # Parse CSV ignoring comments
                    data_lines = [l for l in lines if not l.startswith('#') and l.strip()]
                    # Take the 20 most recent
                    # Columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
                    recent = data_lines[:20]
                    
                    new_spool = []
                    for line in recent:
                        parts = line.split('","')
                        if len(parts) >= 6:
                            url = parts[2].replace('"', '')
                            threat_type = parts[5].replace('"', '').replace('_', ' ').upper()
                            
                            tags = ""
                            if len(parts) > 6:
                                tags = parts[6].replace('"', '')
                            
                            threat_name = threat_type
                            if tags and tags != "None":
                                tag_list = [t for t in tags.split(',') if t.lower() not in ["32-bit", "64-bit", "elf", "exe", "mips", "arm"]]
                                if tag_list:
                                    threat_name = f"{tag_list[0].upper()} {threat_type}"
                            
                            # Extract host
                            host = url.split('://')[-1].split('/')[0]
                            ip = resolve_domain(host)
                            geo = await fetch_geo(ip, client)
                            
                            target = random.choice(POTENTIAL_TARGETS)
                            
                            new_spool.append({
                                "id": parts[0].replace('"', ''),
                                "source": {
                                    "url": url,
                                    "ip": ip or host,
                                    "lat": geo['lat'],
                                    "long": geo['lon'],
                                    "country": geo.get('country', 'Unknown'),
                                    "city": geo.get('city', 'Unknown')
                                },
                                "target": {
                                    "name": target['name'],
                                    "lat": target['lat'],
                                    "long": target['long'],
                                    "country": target['country']
                                },
                                "threat_type": threat_name or "MALWARE PAYLOAD",
                                "severity": "HIGH" if "malware" in threat_type.lower() else "MEDIUM"
                            })
                            await asyncio.sleep(0.5) # Prevent hammering geoip API
                    
                    for news in news_items:
                        target = random.choice(POTENTIAL_TARGETS)
                        new_spool.append({
                            "id": f"NEWS_{random.randint(1000,9999)}",
                            "source": {
                                "url": news["title"],
                                "ip": "",
                                "lat": random.uniform(-60, 60),
                                "long": random.uniform(-180, 180),
                                "country": "INTEL"
                            },
                            "target": {
                                "name": target['name'],
                                "lat": target['lat'],
                                "long": target['long'],
                                "country": target['country']
                            },
                            "threat_type": "INTELLIGENCE BRIEFING",
                            "severity": "INFO",
                            "image": news.get("image", "")
                        })

                    if new_spool:
                        random.shuffle(new_spool)
                        live_attacks_spool = new_spool
                        logger.info(f"Updated live threat spool with {len(new_spool)} vectors.")
            
            except Exception as e:
                logger.error(f"Error in ingest daemon: {e}")
            
            # Refresh every 3 minutes
            await asyncio.sleep(180)

def get_live_threats():
    return live_attacks_spool

async def inject_local_scan(url, verdict, score):
    # Try to resolve geo if it's a URL
    host = url
    if "://" in url:
        host = url.split("://")[-1].split("/")[0]
        
    ip = resolve_domain(host) if host else None
    
    async with httpx.AsyncClient() as client:
        geo = await fetch_geo(ip, client)
        
    target = random.choice(POTENTIAL_TARGETS)
    
    new_threat = {
        "id": f"LOCAL_{random.randint(1000,9999)}",
        "source": {
            "url": url,
            "ip": ip or host or "Unknown",
            "lat": geo['lat'],
            "long": geo['lon'],
            "country": geo.get('country', 'Unknown'),
            "city": geo.get('city', 'Unknown')
        },
        "target": {
            "name": target['name'],
            "lat": target['lat'],
            "long": target['long'],
            "country": target['country']
        },
        "threat_type": verdict.upper() + " (LOCAL SYSTEM DETECT)",
        "severity": "CRITICAL" if score > 60 else "HIGH" if score > 20 else "LOW"
    }
    
    # Inject at the top
    live_attacks_spool.insert(0, new_threat)
    # Keep list manageable
    if len(live_attacks_spool) > 50:
        live_attacks_spool.pop()
    
    logger.info(f"Injected local scan to live map: {url}")
