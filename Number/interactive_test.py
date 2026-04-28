# interactive_test.py
"""
Interactive test console for Mamba OSINT Library
Run with: python interactive_test.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mamba import create_client, EmailReputation, DomainIntel, UsernameSearch, PhoneLookup, IPInvestigator

def interactive_shell():
    """Interactive testing shell"""
    print("\n" + "=" * 60)
    print("  Mamba OSINT Interactive Test Console")
    print("=" * 60)
    print("\nCommands:")
    print("  email <address>     - Check email validation")
    print("  breach <email>      - Check email breach status")
    print("  domain <name>       - DNS lookup for domain")
    print("  whois <domain>      - WHOIS lookup")
    print("  username <name>     - Search username across platforms")
    print("  phone <number>      - Validate phone number")
    print("  ip <address>        - IP geolocation")
    print("  help                - Show this help")
    print("  quit                - Exit")
    print("-" * 60)
    
    client = create_client()
    
    while True:
        try:
            cmd = input("\n🔍 mamba> ").strip()
            
            if not cmd:
                continue
            
            if cmd == "quit" or cmd == "exit":
                break
            elif cmd == "help":
                print("\nCommands:")
                print("  email <address>     - Check email validation")
                print("  breach <email>      - Check email breach status")
                print("  domain <name>       - DNS lookup for domain")
                print("  whois <domain>      - WHOIS lookup")
                print("  username <name>     - Search username across platforms")
                print("  phone <number>      - Validate phone number")
                print("  ip <address>        - IP geolocation")
                print("  quit                - Exit")
            
            elif cmd.startswith("email "):
                email = cmd.split()[1]
                email_module = EmailReputation(client)
                result = email_module.validate_format(email)
                
                if result.success:
                    print(f"✓ Valid email address")
                    print(f"  Format valid: {result.data['valid_format']}")
                    print(f"  MX records: {result.data['has_mx_records']}")
                    if result.data.get('suggestions'):
                        print(f"  Suggestions: {', '.join(result.data['suggestions'])}")
                else:
                    print(f"✗ Invalid email: {result.error}")
            
            elif cmd.startswith("breach "):
                email = cmd.split()[1]
                email_module = EmailReputation(client)
                result = email_module.check_breach(email)
                
                if result.success:
                    if result.data['found_in_breaches']:
                        print(f"⚠️  Email found in {result.data['breach_count']} breaches!")
                    else:
                        print(f"✓ Email not found in known breaches")
                else:
                    print(f"✗ Check failed: {result.error}")
            
            elif cmd.startswith("domain "):
                domain = cmd.split()[1]
                domain_module = DomainIntel(client)
                result = domain_module.dns_records(domain)
                
                if result.success:
                    print(f"✓ DNS records found")
                    for record_type, records in result.data['records'].items():
                        if records:
                            print(f"  {record_type}: {', '.join(records[:3])}")
                else:
                    print(f"✗ DNS lookup failed: {result.error}")
            
            elif cmd.startswith("whois "):
                domain = cmd.split()[1]
                domain_module = DomainIntel(client)
                result = domain_module.whois_lookup(domain)
                
                if result.success:
                    print(f"✓ WHOIS information:")
                    if result.data.get('registrar'):
                        print(f"  Registrar: {result.data['registrar']}")
                    if result.data.get('creation_date'):
                        print(f"  Created: {result.data['creation_date']}")
                    if result.data.get('name_servers'):
                        print(f"  Name Servers: {', '.join(result.data['name_servers'][:3])}")
                else:
                    print(f"✗ WHOIS lookup failed: {result.error}")
            
            elif cmd.startswith("username "):
                username = cmd.split()[1]
                username_module = UsernameSearch(client)
                result = username_module.search(username, max_platforms=10)
                
                if result.success:
                    found = [p for p, v in result.data['platforms'].items() if v['exists']]
                    print(f"✓ Found on {len(found)} platforms:")
                    for platform in found[:5]:
                        print(f"  • {platform}")
                else:
                    print(f"✗ No platforms found or search failed")
            
            elif cmd.startswith("phone "):
                phone = cmd.split()[1]
                phone_module = PhoneLookup(client)
                result = phone_module.validate(phone, "US")
                
                if result.success and result.data['valid']:
                    print(f"✓ Valid phone number")
                    print(f"  Normalized: {result.data['normalized']}")
                    if result.data.get('possible_carrier'):
                        print(f"  Carrier: {result.data['possible_carrier']}")
                else:
                    print(f"✗ Invalid phone number format")
                    if result.data.get('format_hint'):
                        print(f"  Hint: {result.data['format_hint']}")
            
            elif cmd.startswith("ip "):
                ip = cmd.split()[1]
                ip_module = IPInvestigator(client)
                result = ip_module.geolocate(ip)
                
                if result.success:
                    print(f"✓ IP geolocation:")
                    print(f"  Location: {result.data['city']}, {result.data['region']}, {result.data['country']}")
                    print(f"  ISP: {result.data['isp']}")
                    print(f"  Coordinates: {result.data['latitude']}, {result.data['longitude']}")
                else:
                    print(f"✗ Geolocation failed: {result.error}")
            
            else:
                print(f"Unknown command: {cmd}")
                print("Type 'help' for available commands")
        
        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")
    
    client.close()
    print("\nThank you for testing Mamba!")

if __name__ == "__main__":
    interactive_shell()