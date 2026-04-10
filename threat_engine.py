import re
import os
import ssl
import json
import socket
import hashlib
import urllib.request
from urllib.parse import urlparse
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import whois
import dns.resolver
import math
from difflib import SequenceMatcher

class ThreatEngine:
    def __init__(self):
        print("Initializing Deep Heuristic Threat Engine (Enterprise Mode + Phase 3)...")
        self.vt_api_key = "ec56007a59da3a53aef1eae06dba29f63ae347afcb6f79eaa2e28e0e669f5e42"
        self.gemini_api_key = "AIzaSyCCNl_6KH7QnQodPITz_EDLa7Fld9waqtg"
        self.malicious_urls = set()
        self._load_urlhaus()
        
        self.nlp_triggers = [
            'login', 'secure', 'account', 'update', 'verify', 'banking',
            'free', 'bonus', 'claim', 'pwnd', 'password', 'wallets',
            'suspend', 'confirm', 'urgent', 'required', 'authentication',
            'identity', 'validate'
        ]
        
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'bit.do', 'lc.chat'
        ]
        self.suspicious_tlds = ['.xyz', '.top', '.pw', '.cc', '.club', '.online', '.site']

        self.target_brands = ['paypal', 'apple', 'amazon', 'microsoft', 'google', 'netflix', 'chase', 'wellsfargo', 'bankofamerica', 'facebook', 'instagram', 'twitter', 'linkedin']

    def _shannon_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _check_impersonation(self, base_domain):
        # Remove common phishing prefixes/suffixes to get core
        core = base_domain.split('.')[0]
        core = core.replace('secure', '').replace('login', '').replace('auth', '').replace('-', '')
        for brand in self.target_brands:
            if core == brand: # Exact match might be legitimate, bypass typo check
                continue
            similarity = SequenceMatcher(None, core, brand).ratio()
            if similarity > 0.8:
                return brand, similarity
        return None, 0


    def _load_urlhaus(self):
        try:
            req = urllib.request.Request("https://urlhaus.abuse.ch/downloads/text_online/", headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, timeout=10)
            data = response.read().decode('utf-8')
            for line in data.splitlines()[:5000]:
                line = line.strip()
                if line and not line.startswith('#'):
                    self.malicious_urls.add(line)
        except Exception as e:
            pass

    def analyze_message(self, text: str):
        if not self.gemini_api_key:
            return {
                "risk": "Error",
                "score": 0,
                "tactics": ["API Key Missing"],
                "verdict": "Please provide your Gemini API key in threat_engine.py to enable AI contextual analysis."
            }
            
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={self.gemini_api_key}"
        
        prompt = f"""
        You are a top-tier SOC Cyber Threat Analyst. Your job is to read the following email or message and detect Social Engineering and Phishing attempts.
        Analyze the text purely for psychological manipulation: False Urgency, Authority Spoofing, Financial Panic, Scarcity, Malicious Links, etc.
        You must return your analysis STRICTLY as a JSON object, with exactly these four keys:
        "risk": string (must be exactly one of: "Safe", "Suspicious", "Malicious")
        "score": integer (0 to 100, where 100 is explicitly malicious)
        "tactics": list of strings (e.g. ["Urgency", "Spoofing", "Financial Threat"]. Empty list if safe)
        "verdict": string (A concise, 2-sentence explanation of your findings)

        Message to analyze:
        {text}
        """
        
        payload = {
            "contents": [{"parts": [{"text": prompt}]}]
        }
        
        try:
            res = requests.post(url, json=payload, headers={'Content-Type': 'application/json'}, timeout=10)
            data = res.json()
            if 'error' in data:
                return {"risk": "Error", "score": 0, "tactics": ["API Error"], "verdict": data['error'].get('message', 'Unknown Gemini API Error')}
            
            raw_text = data['candidates'][0]['content']['parts'][0]['text']
            raw_text = raw_text.replace('```json', '').replace('```', '').strip()
            result = json.loads(raw_text)
            
            return {
                "risk": result.get("risk", "Unknown"),
                "score": result.get("score", 0),
                "tactics": result.get("tactics", []),
                "verdict": result.get("verdict", "No explanation provided.")
            }
        except Exception as e:
            return {
                "risk": "Error",
                "score": 0,
                "tactics": ["Parsing Error"],
                "verdict": f"Failed to connect to Gemini or parse output. Exception: {str(e)}"
            }

    def generate_url_summary(self, url: str, risk: str, score: int, flags: list, details: dict) -> dict:
        """Call Gemini to generate a plain-language threat summary for URL analysis."""
        if not self.gemini_api_key:
            return {"threat_type": "Unknown", "user_summary": "Gemini API key not configured.", "severity": risk}

        gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={self.gemini_api_key}"

        flags_text = '\n'.join(f'- {f}' for f in flags) if flags else '- No specific flags.'
        details_text = (
            f"Domain: {details.get('domain', 'N/A')}\n"
            f"Global Trust: {details.get('global_trust', 'Unknown')}\n"
            f"SSL Trust: {details.get('ssl_trust', 'Unknown')}\n"
            f"Brand Impersonation: {details.get('brand_impersonation', 'None')}\n"
            f"DNS Integrity: {details.get('dns_integrity', 'Unknown')}\n"
            f"Entropy Score: {details.get('entropy_score', 0)}\n"
            f"NLP Deception Score: {details.get('nlp_deception_score', 0)}\n"
            f"JS Evasion Score: {details.get('js_evasion_score', 0)}\n"
            f"Payload Type: {details.get('payload_type', 'Standard Webpage')}\n"
            f"Punycode Detected: {details.get('punycode_detected', False)}\n"
            f"VT Malicious: {details.get('vt_stats', {}).get('malicious', 0)}\n"
            f"VT Suspicious: {details.get('vt_stats', {}).get('suspicious', 0)}"
        )

        prompt = f"""
You are a cybersecurity expert writing a report for an everyday user (not a technical person).
A URL has been scanned and the following intelligence was collected:

URL: {url}
Risk Level: {risk}
Risk Score: {score}/100

Detected Threat Flags:
{flags_text}

Technical Details:
{details_text}

Based on this data, you must return a JSON object with exactly these three keys:
"threat_type": string — The specific category of threat (e.g., "Phishing Attack", "Malware Distribution", "Command & Control (C2)", "Credential Harvesting", "Brand Impersonation", "Domain Generation Algorithm (DGA)", "URL Shortener Obfuscation", "Parked Domain", "Safe / No Threat", etc.)
"user_summary": string — A 3-4 sentence explanation in simple, plain English explaining WHY this link is dangerous, WHAT the attacker is trying to do, and WHAT could happen to the user if they click it. If safe, explain briefly why it's trustworthy. Be direct and conversational, NOT technical jargon.
"severity": string — Must be exactly one of: "Critical", "High", "Medium", "Low", "Safe"

Return ONLY the JSON object. No markdown, no code blocks, no extra text.
"""

        payload = {"contents": [{"parts": [{"text": prompt}]}]}

        try:
            res = requests.post(gemini_url, json=payload, headers={'Content-Type': 'application/json'}, timeout=30)
            data = res.json()
            if 'error' in data:
                return {"threat_type": "Analysis Error", "user_summary": data['error'].get('message', 'Gemini API error.'), "severity": risk}
            raw_text = data['candidates'][0]['content']['parts'][0]['text']
            raw_text = raw_text.replace('```json', '').replace('```', '').strip()
            result = json.loads(raw_text)
            return {
                "threat_type": result.get("threat_type", "Unknown Threat"),
                "user_summary": result.get("user_summary", "No summary available."),
                "severity": result.get("severity", risk)
            }
        except Exception as e:
            return {"threat_type": "Parse Error", "user_summary": f"Could not generate AI summary: {str(e)}", "severity": risk}

    def analyze(self, url: str):
        flags = []
        score = 0
        is_malicious = False
        details = {
            "domain": "unknown",
            "ip": "unknown",
            "server_location": "unknown",
            "registrar": "unknown",
            "redirects": 0,
            "has_login": False,
            "ssl_trust": "Unknown",
            "dns_integrity": "Unknown",
            "nlp_deception_score": 0,
            "entropy_score": 0.0,
            "brand_impersonation": "None",
            "punycode_detected": False,
            "js_evasion_score": 0,
            "payload_type": "Standard Webpage",
            "global_trust": "Untrusted / Unknown",
            "vt_stats": {"scans": 0, "malicious": 0, "suspicious": 0, "safe": 0}
        }
        
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
            
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            details["domain"] = domain
            hostname = domain.split(':')[0]
            port = parsed.port
            
            # Non-routable checks
            if not hostname or ('.' not in hostname and hostname != 'localhost'):
                return {"risk": "Malicious", "score": 100, "flags": [f"Invalid / Non-Routable Domain Name ('{hostname}')"], "details": details}
            
            # Non-standard Web Port Check
            if port and port not in (80, 443):
                flags.append(f"Abnormal port mapping ({port}). Common in C2/Botnet communications.")
                score += 20
        except:
            return {"risk": "Malicious", "score": 100, "flags": ["Invalid URL Format"], "details": details}

        # 1. URLHaus DB
        if url in self.malicious_urls:
            flags.append("Identified in Global Threat Database (Active Threat)")
            score = 100
            is_malicious = True

        # 2. Entropy, Lexical, Typosquatting
        is_globally_trusted = False
        if hostname:
            base_domain = hostname.split('.')[-2] + '.' + hostname.split('.')[-1] if len(hostname.split('.')) > 1 else hostname
            
            # Tranco API Global Trust check
            if not is_malicious:
                try:
                    tranco_res = requests.get(f"https://tranco-list.eu/api/ranks/domain/{base_domain}", timeout=2).json()
                    if tranco_res.get('ranks') and len(tranco_res['ranks']) > 0:
                        rank = tranco_res['ranks'][0]['rank']
                        if rank < 100000:
                            details["global_trust"] = f"Top 100k (Rank #{rank})"
                            flags.append(f"Globally Trusted Domain (Tranco Rank #{rank}). Safe-listed from heuristic penalities.")
                            is_globally_trusted = True
                except:
                    pass
                    
            # VirusTotal API Enterprise Check
            if not is_malicious:
                try:
                    vt_headers = {'x-apikey': self.vt_api_key}
                    vt_res = requests.get(f"https://www.virustotal.com/api/v3/domains/{base_domain}", headers=vt_headers, timeout=4).json()
                    stats = vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    if stats:
                        vt_malicious = stats.get('malicious', 0)
                        vt_suspicious = stats.get('suspicious', 0)
                        vt_harmless = stats.get('harmless', 0)
                        vt_undetected = stats.get('undetected', 0)
                        total_scans = vt_malicious + vt_suspicious + vt_harmless + vt_undetected
                        
                        details['vt_stats'] = {
                            "scans": total_scans,
                            "malicious": vt_malicious,
                            "suspicious": vt_suspicious,
                            "safe": vt_harmless + vt_undetected
                        }
                        
                        if vt_malicious >= 3:
                            flags.append(f"Global Consensus Alert: {vt_malicious} AV vendors flagged this domain as malware on VirusTotal.")
                            score += 50
                        elif vt_malicious > 0:
                            flags.append(f"VirusTotal Warning: {vt_malicious} AV vendor(s) flagged this domain.")
                            score += 25
                            
                        if vt_suspicious >= 2:
                            flags.append(f"VirusTotal Suspicion: {vt_suspicious} vendors marked domain as suspicious.")
                            score += 15
                except:
                    pass

            entropy = self._shannon_entropy(base_domain)
            details["entropy_score"] = round(entropy, 2)
            if not is_globally_trusted:
                if entropy > 4.0:
                    flags.append(f"Extremely high domain randomness (Shannon Entropy: {entropy:.2f}). Possible DGA.")
                    score += 35
                elif entropy > 3.5:
                    flags.append(f"High domain randomness (Shannon Entropy: {entropy:.2f}).")
                    score += 15

                # Brand Impersonation Typosquatting
                impersonated_brand, sim_score = self._check_impersonation(base_domain)
                if impersonated_brand:
                    details["brand_impersonation"] = f"Mimicking '{impersonated_brand.title()}'"
                    flags.append(f"Mathematical Typosquatting detected: Spoofing '{impersonated_brand.title()}' ({int(sim_score*100)}% lexical similarity).")
                    score += 65 # Very high penalty

            # Punycode / IDN
            if 'xn--' in domain:
                details["punycode_detected"] = True
                flags.append("Warning: Internationalized Domain Name (Punycode) detected. Often used for Homograph visual spoofing.")
                score += 50

            if '@' in url:
                flags.append("URL contains '@' symbol to obfuscate the real destination.")
                score += 60

        # Live Payload Inspection & Final Destination Routing
        response_obj = None
        if not is_malicious and "localhost" not in domain and hostname:
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/100.0.4896.127'}
                response_obj = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
                
                # Update tracking host to the final redirected destination
                final_url = response_obj.url
                final_parsed = urlparse(final_url)
                hostname = final_parsed.netloc.split(':')[0]
                
                if len(response_obj.history) > 1:
                    details["redirects"] = len(response_obj.history)
                    flags.append(f"Suspicious redirection chain discovered ({len(response_obj.history)} hops)")
                    score += 20
                elif len(response_obj.history) == 1:
                    details["redirects"] = 1
            except requests.RequestException:
                flags.append("Server refused or dropped connection during live payload inspection.")
                score += 10

        # DNS and Crypto Analysis (Using final hostname)
        if not is_malicious and hostname:
            try:
                ip = socket.gethostbyname(hostname)
                details["ip"] = ip
                try:
                    ip_info = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
                    if ip_info.get("status") == "success":
                        country = ip_info.get("country", "Unknown")
                        isp = ip_info.get("isp", "Unknown")
                        
                        # Add CDN Context for explicit UI clarification
                        cdn_providers = ['akamai', 'cloudflare', 'fastly', 'amazon', 'google', 'microsoft', 'cloudfront']
                        if any(c in isp.lower() for c in cdn_providers):
                            details["server_location"] = f"{country} ({isp} Edge CDN)"
                            flags.append("Domain traffic is proxied through a CDN. The resolved IP is a shared edge node. Do NOT visit this IP directly in a browser or it will throw an Error 1003 (Direct IP Access Blocked).")
                        else:
                            details["server_location"] = f"{country} ({isp})"
                            
                        if ip_info.get("hosting", False):
                            flags.append("Hosted on known datacenter/proxy IP (Avoids residential tracability)")
                            score += 10
                except:
                    pass
            except socket.gaierror:
                flags.append("Domain name does not resolve to an IP address (Dead/Fake Domain)")
                score += 100
                is_malicious = True

            try:
                final_base_domain = hostname.split('.')[-2] + '.' + hostname.split('.')[-1] if len(hostname.split('.')) > 1 else hostname
                mx_records = dns.resolver.resolve(final_base_domain, 'MX')
                details["dns_integrity"] = f"Valid ({len(mx_records)} MX Records)"
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                details["dns_integrity"] = "No MX Records"
                flags.append("Domain lacks Mail Exchange (MX) records. Unusual for legitimate business domains.")
                score += 15
            except Exception:
                details["dns_integrity"] = "Unverifiable"

        if hostname and "localhost" not in domain:
            try:
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
                s.settimeout(3)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                details["ssl_trust"] = "Valid / Secure"
                issuer = dict(x[0] for x in cert.get('issuer', []))
                if 'Let\'s Encrypt' in str(issuer.get('organizationName', '')):
                    details["ssl_trust"] = "Let's Encrypt (Free Tier)"
            except ssl.SSLCertVerificationError:
                details["ssl_trust"] = "Expired / Invalid"
                flags.append("SSL Certificate is expired, self-signed, or untrusted.")
                score += 35
            except (socket.timeout, ConnectionRefusedError):
                details["ssl_trust"] = "No HTTPS / Refused"
                if url.startswith('https'):
                    flags.append("HTTPS requested but server refused connection. Highly insecure.")
                    score += 20
            except Exception:
                details["ssl_trust"] = "Failed Validation"

        # Content Types and JS Evasions
        if response_obj and not is_malicious:
            try:
                # Intercept File Payload
                content_type = response_obj.headers.get('Content-Type', '').lower()
                executable_types = ['application/x-msdownload', 'application/vnd.android.package-archive', 'application/x-dosexec']
                if any(t in content_type for t in executable_types) or url.endswith(('.exe', '.apk', '.scr', '.vbs')):
                    details["payload_type"] = "Executable Warning (Malware Risk)"
                    flags.append(f"URL points directly to an executable file/installer ({content_type}). Extreme Risk.")
                    score += 80
                
                soup = BeautifulSoup(response_obj.text, 'html.parser')
                pass_inputs = soup.find_all('input', type='password')
                if pass_inputs:
                    details["has_login"] = True
                    flags.append("Contains active password forms (Potential Phishing Setup)")
                    score += 30

                page_text = soup.get_text().lower()
                triggers_found = sum(1 for kw in self.nlp_triggers if kw in page_text)
                details["nlp_deception_score"] = float(triggers_found)
                if triggers_found > 5:
                    flags.append(f"High density of deceptive NLP phrases ({triggers_found} triggers).")
                    score += 25
                elif triggers_found > 2:
                    flags.append("Moderate density of urgent/login-related phrases.")
                    score += 10
                    
                # Parked Domain Detection
                parking_keywords = ['domain is for sale', 'buy this domain', 'hugedomains.com', 'domain parking', 'inquire about this domain', 'this domain may be for sale']
                if any(kw in page_text for kw in parking_keywords) or any(kw in response_obj.url for kw in ['hugedomains', 'dan.com', 'sedo.com']):
                    details["payload_type"] = "Parked / For Sale"
                    flags.append("Domain is explicitly parked or listed for sale (No active business hosting).")
                    score += 20
                    
                # JS Evasion Parsing
                js_evasions = 0
                for script in soup.find_all('script'):
                    if script.string:
                        js_text = script.string.lower()
                        # Detect packed scripts / base64 heavy / extreme eval use
                        if js_text.count('eval(') > 2 or js_text.count('atob(') > 2 or js_text.count('unescape(') > 2:
                            js_evasions += 1
                        if len(js_text) > 5000 and '\n' not in js_text[:5000]: # One liner obfuscation common in kits
                            js_evasions += 1
                details["js_evasion_score"] = js_evasions
                if js_evasions > 0:
                    flags.append(f"Detected {js_evasions} highly obfuscated JavaScript blocks (Exploit Kit Indicator).")
                    score += 40

            except Exception:
                pass

        if not is_malicious and "localhost" not in domain and hostname:
            try:
                domain_info = whois.whois(hostname)
                details["registrar"] = domain_info.registrar if domain_info.registrar else "Unknown"
                if domain_info.creation_date:
                    creation = domain_info.creation_date
                    if isinstance(creation, list):
                        creation = creation[0]
                    days_old = (datetime.now() - creation).days
                    if days_old < 30:
                        flags.append(f"Domain is extremely new (Created {days_old} days ago).")
                        score += 30
                    elif days_old < 90:
                        flags.append(f"Domain is young (Created {days_old} days ago).")
                        score += 15
            except:
                pass

        for shortener in self.url_shorteners:
            if shortener in domain:
                flags.append(f"Hides destination via URL shortener ({shortener})")
                score += 25
                break

        # Override score if trusted by Tranco and NOT explicitly banned by URLHaus or VT
        vt_malicious = details.get('vt_stats', {}).get('malicious', 0)
        if is_globally_trusted and url not in self.malicious_urls and vt_malicious == 0:
            score = 0
            is_malicious = False

        score = min(score, 100)
        risk = "Safe"
        if score >= 65:
            risk = "Malicious"
        elif score >= 35:
            risk = "Suspicious"

        if score == 0 and not is_globally_trusted:
            flags.append("No active threat signatures or suspicious heuristics detected.")

        return {
            "risk": risk,
            "score": score,
            "flags": flags,
            "details": details
        }

    def analyze_file(self, filename: str, file_bytes: bytes):
        score = 0
        flags = []
        details = {
            "filename": filename,
            "size": len(file_bytes),
            "md5": "unknown",
            "sha256": "unknown",
            "entropy": 0.0,
            "vt_stats": {"scans": 0, "malicious": 0, "suspicious": 0, "safe": 0},
            "file_type": "Data"
        }

        # Calculate hashes
        details["md5"] = hashlib.md5(file_bytes).hexdigest()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        details["sha256"] = sha256_hash

        # Calculate Entropy
        entropy = self._shannon_entropy(file_bytes)
        details["entropy"] = round(entropy, 2)
        if entropy > 7.3:
            flags.append(f"Extremely high entropy ({details['entropy']}). Indicates packing or encryption, common in malware droppers.")
            score += 35
        elif entropy > 6.8:
            flags.append(f"High entropy ({details['entropy']}). Usually indicates highly compressed data.")
            score += 15

        # Heuristic Analysis based on extension
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        if ext in ['exe', 'scr', 'vbs', 'ps1', 'bat', 'cmd', 'apk', 'dll', 'msi']:
            details["file_type"] = f"Executable ({ext.upper()})"
            flags.append(f"Executable file type ({ext.upper()}) detected. High intrinsic risk.")
            score += 20
        elif ext in ['zip', 'rar', '7z', 'tar', 'gz']:
            details["file_type"] = f"Archive ({ext.upper()})"
            flags.append(f"Archive file type ({ext.upper()}) commonly used to evade basic scanners.")
            score += 10
        elif ext in ['doc', 'docm', 'xls', 'xlsm', 'xlb', 'pdf']:
            details["file_type"] = f"Document ({ext.upper()})"
            flags.append(f"Document format ({ext.upper()}) supporting active macros/scripts.")
            score += 15
        else:
            details["file_type"] = f"Standard File ({ext.upper()})"
            
        # VT Engine Hash Lookup
        try:
            vt_headers = {'x-apikey': self.vt_api_key}
            vt_res = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256_hash}", headers=vt_headers, timeout=5)
            
            if vt_res.status_code == 200:
                stats = vt_res.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                if stats:
                    vt_malicious = stats.get('malicious', 0)
                    vt_suspicious = stats.get('suspicious', 0)
                    vt_harmless = stats.get('harmless', 0)
                    vt_undetected = stats.get('undetected', 0)
                    total_scans = vt_malicious + vt_suspicious + vt_harmless + vt_undetected
                    
                    details['vt_stats'] = {
                        "scans": total_scans,
                        "malicious": vt_malicious,
                        "suspicious": vt_suspicious,
                        "safe": vt_harmless + vt_undetected
                    }
                    
                    if vt_malicious >= 3:
                        flags.append(f"Global Consensus Alert: {vt_malicious} AV vendors flagged this file signature as MALWARE.")
                        score += 65
                    elif vt_malicious > 0:
                        flags.append(f"VirusTotal Warning: {vt_malicious} AV vendor(s) flagged this file.")
                        score += 30
                        
                    if vt_suspicious >= 2:
                        flags.append(f"VirusTotal Suspicion: {vt_suspicious} vendors marked file as suspicious.")
                        score += 15
            elif vt_res.status_code == 404:
                flags.append("File hash not found in global threat database (Zero-Day or Custom/Safe target).")
                details['vt_stats']['scans'] = 0
        except Exception as e:
            pass
            
        score = min(score, 100)
        risk = "Safe"
        if score >= 65:
            risk = "Malicious"
        elif score >= 35:
            risk = "Suspicious"
            
        if score == 0:
            flags.append("No active threat signatures or suspicious heuristics detected statically.")
            
        return {
            "risk": risk,
            "score": score,
            "flags": flags,
            "details": details
        }
        
    def generate_file_summary(self, filename: str, risk: str, score: int, flags: list, details: dict) -> dict:
        if not self.gemini_api_key:
            return {"threat_type": "Unknown", "user_summary": "Gemini API key not configured.", "severity": risk}

        gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={self.gemini_api_key}"

        flags_text = '\n'.join(f'- {f}' for f in flags) if flags else '- No specific flags.'
        details_text = (
            f"Filename: {details.get('filename')}\n"
            f"File Type: {details.get('file_type')}\n"
            f"Size: {details.get('size')} bytes\n"
            f"Entropy: {details.get('entropy')}\n"
            f"SHA256: {details.get('sha256')}\n"
            f"VT Malicious: {details.get('vt_stats', {}).get('malicious', 0)}\n"
            f"VT Suspicious: {details.get('vt_stats', {}).get('suspicious', 0)}"
        )

        prompt = f"""
You are a cybersecurity expert writing a report for an everyday user.
A File has been scanned statically and the following telemetry was collected:

Filename: {filename}
Risk Level: {risk}
Risk Score: {score}/100

Detected Threat Flags:
{flags_text}

Technical Details:
{details_text}

Based on this data, you must return a JSON object with exactly these three keys:
"threat_type": string — Category (e.g., "Trojan Dropper", "Ransomware Payload", "Suspicious Document", "Packed Executable", "Safe Document", etc.)
"user_summary": string — A 3-4 sentence explanation in plain English about why this file is safe or dangerous, based on the entropy and AV consensus. Be direct.
"severity": string — Must be exactly one of: "Critical", "High", "Medium", "Low", "Safe"

Return ONLY the JSON object. No markdown, no code blocks, no extra text.
"""
        payload = {"contents": [{"parts": [{"text": prompt}]}]}

        try:
            res = requests.post(gemini_url, json=payload, headers={'Content-Type': 'application/json'}, timeout=30)
            data = res.json()
            if 'error' in data:
                return {"threat_type": "Analysis Error", "user_summary": data['error'].get('message', 'Gemini API error.'), "severity": risk}
            raw_text = data['candidates'][0]['content']['parts'][0]['text']
            raw_text = raw_text.replace('```json', '').replace('```', '').strip()
            result = json.loads(raw_text)
            return {
                "threat_type": result.get("threat_type", "Unknown Threat"),
                "user_summary": result.get("user_summary", "No summary available."),
                "severity": result.get("severity", risk)
            }
        except Exception as e:
            return {"threat_type": "Parse Error", "user_summary": f"Could not generate AI summary: {str(e)}", "severity": risk}
