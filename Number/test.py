from mamba import MambaClient, EmailReputation, DomainIntel

# Create client
client = MambaClient()

# Email validation
email = EmailReputation(client)
result = email.validate_format("user@example.com")
print(f"Valid: {result.success}")
print(f"MX Records: {result.data['has_mx_records']}")

# Domain WHOIS
domain = DomainIntel(client)
result = domain.whois_lookup("google.com")
print(f"Registrar: {result.data['registrar']}")

# Clean up
client.close()