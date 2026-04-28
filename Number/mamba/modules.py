"""
OSINT modules for email, domain, username, phone, and IP investigations
"""

import re
import hashlib
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

from .core import OSINTResult, MambaClient


class EmailReputation:
    """Email reputation, breach checking, and validation"""
    
    def __init__(self, client: MambaClient):
        self.client = client
    
    def check_breach(self, email: str) -> OSINTResult:
        """Check if email appears in known data breaches"""
        if not self._validate_email(email):
            return OSINTResult(
                success=False,
                data={},
                source="HaveIBeenPwned",
                query=email,
                error="Invalid email format"
            )
        
        email_hash = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        prefix = email_hash[:5]
        suffix = email_hash[5:]
        
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = self.client.request("GET", url)
        
        if response and "error" not in response:
            breaches = []
            text_content = response.get("text", "")
            
            for line in text_content.splitlines():
                if line.startswith(suffix):
                    count = line.split(':')[1] if ':' in line else '0'
                    breaches.append({
                        "hash_suffix": suffix,
                        "breach_count": int(count)
                    })
            
            return OSINTResult(
                success=True,
                data={
                    "email": email,
                    "found_in_breaches": len(breaches) > 0,
                    "breach_count": len(breaches),
                    "details": breaches
                },
                source="HaveIBeenPwned",
                query=email
            )
        
        return OSINTResult(
            success=False,
            data={"email": email},
            source="HaveIBeenPwned",
            query=email,
            error=response.get("error", "Failed to check breaches") if response else "Connection failed"
        )
    
    def validate_format(self, email: str) -> OSINTResult:
        """Validate email format and domain MX records"""
        is_valid_format = self._validate_email(email)
        domain = email.split('@')[-1] if '@' in email else None
        
        has_mx = False
        mx_records = []
        
        if domain and DNS_AVAILABLE:
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                has_mx = len(answers) > 0
                mx_records = [str(r.exchange) for r in answers]
            except:
                has_mx = False
        
        return OSINTResult(
            success=is_valid_format and has_mx if DNS_AVAILABLE else is_valid_format,
            data={
                "email": email,
                "valid_format": is_valid_format,
                "has_mx_records": has_mx if DNS_AVAILABLE else "DNS module not installed",
                "domain": domain,
                "mx_records": mx_records[:5] if mx_records else [],
                "suggestions": self._get_suggestions(email) if not is_valid_format else []
            },
            source="EmailValidator",
            query=email
        )
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format using regex"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _get_suggestions(self, email: str) -> List[str]:
        """Get suggestions for common email typos"""
        suggestions = []
        common_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com']
        
        if '@' not in email:
            return suggestions
        
        local_part = email.split('@')[0]
        for common in common_domains:
            suggestions.append(f"{local_part}@{common}")
        
        return suggestions[:3]
    
    def generate_alternatives(self, email: str) -> OSINTResult:
        """Generate possible email variations"""
        if '@' not in email:
            return OSINTResult(
                success=False,
                data={},
                source="EmailVariations",
                query=email,
                error="Invalid email format"
            )
        
        local_part, domain = email.split('@')
        parts = re.split(r'[._-]', local_part)
        
        variations = set()
        variations.add(email)
        
        if len(parts) >= 2:
            variations.add(f"{parts[0]}.{parts[-1]}@{domain}")
            variations.add(f"{parts[0]}_{parts[-1]}@{domain}")
            variations.add(f"{parts[0]}{parts[-1]}@{domain}")
        
        if len(parts) >= 1:
            initials = ''.join(p[0] for p in parts if p)
            if initials:
                variations.add(f"{initials}@{domain}")
        
        variations.add(local_part.replace('.', '') + "@" + domain)
        variations.add(local_part.replace('_', '') + "@" + domain)
        
        return OSINTResult(
            success=True,
            data={
                "original": email,
                "variations": list(variations)[:10],
                "total_variations": len(variations)
            },
            source="EmailVariations",
            query=email
        )


class DomainIntel:
    """Domain intelligence and reconnaissance"""
    
    def __init__(self, client: MambaClient):
        self.client = client
    
    def whois_lookup(self, domain: str) -> OSINTResult:
        """Perform WHOIS lookup for domain"""
        if not WHOIS_AVAILABLE:
            return OSINTResult(
                success=False,
                data={},
                source="WHOIS",
                query=domain,
                error="python-whois module not installed"
            )
        
        try:
            domain_clean = re.sub(r'^https?://', '', domain)
            domain_clean = domain_clean.split('/')[0]
            domain_clean = domain_clean.split(':')[0]
            
            w = whois.whois(domain_clean)
            
            data = {
                "domain": domain_clean,
                "registrar": str(w.registrar) if w.registrar else None,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "updated_date": str(w.updated_date) if w.updated_date else None,
                "name_servers": w.name_servers[:5] if w.name_servers else [],
                "status": w.status[:5] if w.status else [],
                "emails": w.emails[:5] if w.emails else [],
                "org": str(w.org) if w.org else None,
                "name": str(w.name) if w.name else None
            }
            
            return OSINTResult(
                success=True,
                data=data,
                source="WHOIS",
                query=domain
            )
            
        except Exception as e:
            return OSINTResult(
                success=False,
                data={"domain": domain},
                source="WHOIS",
                query=domain,
                error=f"WHOIS lookup failed: {str(e)[:100]}"
            )
    
    def dns_records(self, domain: str, record_types: List[str] = None) -> OSINTResult:
        """Fetch DNS records for domain"""
        if not DNS_AVAILABLE:
            return OSINTResult(
                success=False,
                data={},
                source="DNS",
                query=domain,
                error="dnspython module not installed"
            )
        
        if record_types is None:
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
        
        records = {}
        domain_clean = re.sub(r'^https?://', '', domain).split('/')[0]
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain_clean, record_type)
                records[record_type] = [str(answer) for answer in answers][:10]
            except:
                records[record_type] = []
        
        has_records = any(len(v) > 0 for v in records.values())
        
        return OSINTResult(
            success=has_records,
            data={
                "domain": domain_clean,
                "records": records,
                "total_record_types": len([k for k, v in records.items() if v])
            },
            source="DNS",
            query=domain
        )
    
    def subdomain_enumeration(self, domain: str, custom_list: List[str] = None) -> OSINTResult:
        """Enumerate common subdomains"""
        if not DNS_AVAILABLE:
            return OSINTResult(
                success=False,
                data={},
                source="SubdomainEnum",
                query=domain,
                error="dnspython module not installed"
            )
        
        common_subdomains = custom_list or [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cpanel', 'whm', 'webdisk', 'autodiscover', 'autoconfig', 'test',
            'api', 'blog', 'docs', 'admin', 'dev', 'staging', 'app', 'shop',
            'cdn', 'static', 'assets', 'img', 'video', 'support', 'help'
        ]
        
        found = []
        domain_clean = re.sub(r'^https?://', '', domain).split('/')[0]
        
        for sub in common_subdomains[:50]:
            full_domain = f"{sub}.{domain_clean}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    found.append({
                        "subdomain": full_domain,
                        "ip": str(answers[0])
                    })
            except:
                pass
        
        return OSINTResult(
            success=len(found) > 0,
            data={
                "domain": domain_clean,
                "found_subdomains": found,
                "total_found": len(found),
                "total_checked": len(common_subdomains[:50])
            },
            source="SubdomainEnum",
            query=domain
        )


class UsernameSearch:
    """Search for username across multiple online platforms"""
    
    def __init__(self, client: MambaClient):
        self.client = client
        self.platforms = {
            "GitHub": "https://github.com/{}",
            "Twitter": "https://twitter.com/{}",
            "Reddit": "https://reddit.com/user/{}",
            "Medium": "https://medium.com/@{}",
            "Dev.to": "https://dev.to/{}",
            "Pinterest": "https://pinterest.com/{}",
            "YouTube": "https://youtube.com/@{}",
            "Twitch": "https://twitch.tv/{}",
            "GitLab": "https://gitlab.com/{}",
            "Bitbucket": "https://bitbucket.org/{}/"
        }
    
    def search(self, username: str, max_platforms: int = 15) -> OSINTResult:
        """Search for username across multiple platforms"""
        results = {}
        checked = 0
        
        for platform, url_template in list(self.platforms.items())[:max_platforms]:
            url = url_template.format(username)
            response = self.client.request("GET", url)
            
            if response and "error" not in response:
                results[platform] = {
                    "exists": True,
                    "url": url,
                    "status": "active"
                }
            else:
                status_code = response.get("status_code") if response else None
                results[platform] = {
                    "exists": False,
                    "url": url,
                    "status": "not_found" if status_code == 404 else "error"
                }
            checked += 1
        
        found_count = sum(1 for v in results.values() if v["exists"])
        
        return OSINTResult(
            success=found_count > 0,
            data={
                "username": username,
                "platforms": results,
                "found_on": found_count,
                "total_checked": checked,
                "success_rate": f"{(found_count/checked)*100:.1f}%" if checked > 0 else "0%"
            },
            source="UsernameSearch",
            query=username
        )
    
    def add_platform(self, name: str, url_template: str):
        """Add custom platform to search"""
        self.platforms[name] = url_template


class PhoneLookup:
    """Phone number lookup and validation"""
    
    def __init__(self, client: MambaClient):
        self.client = client
    
    def validate(self, phone: str, country_code: str = "US") -> OSINTResult:
        """Validate phone number format"""
        patterns = {
            "US": r'^\+?1?\s*\(?[0-9]{3}\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}$',
            "UK": r'^\+?44\s*\(?[0-9]{4}\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{3}$',
            "IN": r'^\+?91\s*[6-9][0-9]{9}$',
            "CA": r'^\+?1\s*\(?[0-9]{3}\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}$',
            "AU": r'^\+?61\s*\(?[0-9]{1}\)?[\s.-]?[0-9]{4}[\s.-]?[0-9]{4}$',
            "DE": r'^\+?49\s*\(?[0-9]{3,5}\)?[\s.-]?[0-9]{3,8}$'
        }
        
        pattern = patterns.get(country_code.upper(), patterns["US"])
        is_valid = bool(re.match(pattern, phone.strip()))
        
        cleaned = re.sub(r'[^\d+]', '', phone)
        
        return OSINTResult(
            success=is_valid,
            data={
                "phone": phone,
                "valid": is_valid,
                "country": country_code.upper(),
                "normalized": cleaned,
                "length": len(cleaned),
                "possible_carrier": self._guess_carrier(cleaned, country_code) if is_valid else None,
                "format_hint": self._get_format_hint(country_code)
            },
            source="PhoneValidator",
            query=phone
        )
    
    def _guess_carrier(self, phone: str, country: str) -> str:
        """Guess carrier based on number prefixes"""
        if country.upper() == "US" and len(phone) >= 10:
            prefix = phone[-10:-7]
            
            verizon_prefixes = ['201', '202', '301', '310', '410', '510']
            tmobile_prefixes = ['206', '213', '281', '310', '404', '612']
            att_prefixes = ['210', '214', '240', '248', '260', '404']
            
            if prefix in verizon_prefixes:
                return "Verizon (possible)"
            elif prefix in tmobile_prefixes:
                return "T-Mobile (possible)"
            elif prefix in att_prefixes:
                return "AT&T (possible)"
        
        return "Carrier detection not available"
    
    def _get_format_hint(self, country: str) -> str:
        """Get format hint for phone numbers"""
        hints = {
            "US": "Format: +1 (234) 567-8900",
            "UK": "Format: +44 20 1234 5678",
            "IN": "Format: +91 98765 43210",
            "CA": "Format: +1 (234) 567-8900",
            "AU": "Format: +61 2 1234 5678",
            "DE": "Format: +49 30 12345678"
        }
        return hints.get(country.upper(), "Use international format with country code")


class IPInvestigator:
    """IP address investigation and geolocation"""
    
    def __init__(self, client: MambaClient):
        self.client = client
    
    def geolocate(self, ip: str) -> OSINTResult:
        """Get geolocation data for IP address"""
        if not self._validate_ip(ip):
            return OSINTResult(
                success=False,
                data={},
                source="IPGeolocation",
                query=ip,
                error="Invalid IP address format"
            )
        
        url = f"http://ip-api.com/json/{ip}"
        response = self.client.request("GET", url)
        
        if response and response.get("status") == "success":
            return OSINTResult(
                success=True,
                data={
                    "ip": ip,
                    "country": response.get("country"),
                    "country_code": response.get("countryCode"),
                    "region": response.get("regionName"),
                    "city": response.get("city"),
                    "zip": response.get("zip"),
                    "latitude": response.get("lat"),
                    "longitude": response.get("lon"),
                    "timezone": response.get("timezone"),
                    "isp": response.get("isp"),
                    "organization": response.get("org"),
                    "as_number": response.get("as")
                },
                source="IPGeolocation",
                query=ip
            )
        
        return OSINTResult(
            success=False,
            data={"ip": ip},
            source="IPGeolocation",
            query=ip,
            error=response.get("message", "Failed to geolocate IP") if response else "Connection failed"
        )
    
    def reputation_check(self, ip: str) -> OSINTResult:
        """Check IP reputation"""
        if not self._validate_ip(ip):
            return OSINTResult(
                success=False,
                data={},
                source="IPReputation",
                query=ip,
                error="Invalid IP address format"
            )
        
        return OSINTResult(
            success=True,
            data={
                "ip": ip,
                "note": "API key required for detailed reputation. Set with: client.set_api_key('abuseipdb', 'your-key')"
            },
            source="IPReputation",
            query=ip
        )
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IPv4 address format"""
        pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(pattern, ip.strip()))