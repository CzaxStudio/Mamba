# mamba/cli.py
"""
Command-line interface for Mamba OSINT library
"""

import argparse
import sys
import json
from mamba.core import MambaClient
from mamba.modules import (
    EmailReputation,
    DomainIntel,
    UsernameSearch,
    PhoneLookup,
    IPInvestigator
)
from mamba.utils import ResultFormatter


def main():
    parser = argparse.ArgumentParser(
        prog="mamba",
        description="Mamba OSINT - Powerful intelligence gathering tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  mamba email breach user@example.com
  mamba email validate user@example.com
  mamba domain whois google.com
  mamba domain dns google.com
  mamba username johndoe
  mamba phone +1234567890
  mamba ip 8.8.8.8
  mamba ip geo 8.8.8.8
        """
    )
    
    parser.add_argument("--api-key", "-k", help="API key for services (format: service:key)")
    parser.add_argument("--format", "-f", choices=["json", "csv", "table", "markdown"], default="table", 
                       help="Output format (default: table)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Email commands
    email_parser = subparsers.add_parser("email", help="Email OSINT operations")
    email_subparsers = email_parser.add_subparsers(dest="email_command", required=True)
    
    email_breach = email_subparsers.add_parser("breach", help="Check email in breaches")
    email_breach.add_argument("email", help="Email address to check")
    
    email_validate = email_subparsers.add_parser("validate", help="Validate email format")
    email_validate.add_argument("email", help="Email address to validate")
    
    email_variations = email_subparsers.add_parser("variations", help="Generate email variations")
    email_variations.add_argument("email", help="Email address")
    
    # Domain commands
    domain_parser = subparsers.add_parser("domain", help="Domain OSINT operations")
    domain_subparsers = domain_parser.add_subparsers(dest="domain_command", required=True)
    
    domain_whois = domain_subparsers.add_parser("whois", help="WHOIS lookup")
    domain_whois.add_argument("domain", help="Domain name")
    
    domain_dns = domain_subparsers.add_parser("dns", help="DNS records lookup")
    domain_dns.add_argument("domain", help="Domain name")
    domain_dns.add_argument("--types", "-t", help="Record types (comma-separated, e.g., A,MX,TXT)")
    
    domain_subdomain = domain_subparsers.add_parser("subdomains", help="Enumerate subdomains")
    domain_subdomain.add_argument("domain", help="Domain name")
    
    # Username command
    username_parser = subparsers.add_parser("username", help="Search username across platforms")
    username_parser.add_argument("username", help="Username to search")
    username_parser.add_argument("--max", "-m", type=int, default=15, help="Maximum platforms to check")
    
    # Phone command
    phone_parser = subparsers.add_parser("phone", help="Phone number validation")
    phone_parser.add_argument("phone", help="Phone number")
    phone_parser.add_argument("--country", "-c", default="US", help="Country code (US, UK, IN, CA, AU, DE)")
    
    # IP commands
    ip_parser = subparsers.add_parser("ip", help="IP address investigation")
    ip_subparsers = ip_parser.add_subparsers(dest="ip_command", required=True)
    
    ip_geo = ip_subparsers.add_parser("geo", help="IP geolocation")
    ip_geo.add_argument("ip", help="IP address")
    
    ip_reputation = ip_subparsers.add_parser("reputation", help="IP reputation check")
    ip_reputation.add_argument("ip", help="IP address")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Setup client
    api_keys = {}
    if args.api_key:
        try:
            service, key = args.api_key.split(":", 1)
            api_keys[service] = key
        except ValueError:
            print("Error: API key format should be 'service:key'", file=sys.stderr)
            sys.exit(1)
    
    with MambaClient(api_keys=api_keys) as client:
        results = []
        
        try:
            if args.command == "email":
                email_module = EmailReputation(client)
                
                if args.email_command == "breach":
                    result = email_module.check_breach(args.email)
                elif args.email_command == "validate":
                    result = email_module.validate_format(args.email)
                elif args.email_command == "variations":
                    result = email_module.generate_alternatives(args.email)
                else:
                    email_parser.print_help()
                    sys.exit(1)
                results.append(result)
            
            elif args.command == "domain":
                domain_module = DomainIntel(client)
                
                if args.domain_command == "whois":
                    result = domain_module.whois_lookup(args.domain)
                elif args.domain_command == "dns":
                    record_types = args.types.split(",") if args.types else None
                    result = domain_module.dns_records(args.domain, record_types)
                elif args.domain_command == "subdomains":
                    result = domain_module.subdomain_enumeration(args.domain)
                else:
                    domain_parser.print_help()
                    sys.exit(1)
                results.append(result)
            
            elif args.command == "username":
                username_module = UsernameSearch(client)
                result = username_module.search(args.username, max_platforms=args.max)
                results.append(result)
            
            elif args.command == "phone":
                phone_module = PhoneLookup(client)
                result = phone_module.validate(args.phone, args.country)
                results.append(result)
            
            elif args.command == "ip":
                ip_module = IPInvestigator(client)
                
                if args.ip_command == "geo":
                    result = ip_module.geolocate(args.ip)
                elif args.ip_command == "reputation":
                    result = ip_module.reputation_check(args.ip)
                else:
                    ip_parser.print_help()
                    sys.exit(1)
                results.append(result)
            
            # Output results
            if args.format == "json":
                print(ResultFormatter.to_json(results))
            elif args.format == "csv":
                print(ResultFormatter.to_csv(results))
            elif args.format == "markdown":
                print(ResultFormatter.to_markdown(results))
            else:  # table
                print(ResultFormatter.to_table(results))
            
            if args.verbose and hasattr(client.rate_limiter, 'calls_per_second'):
                print(f"\n[Rate limit: {client.rate_limiter.calls_per_second} req/sec]", file=sys.stderr)
        
        except KeyboardInterrupt:
            print("\nInterrupted by user", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    main()