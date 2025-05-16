import sys
import argparse
import socket
from ipaddress import ip_address
import dns.resolver

# API keys (replace with your own if not using --no-api)
VIRUSTOTAL_API_KEY = ""
ABUSEIPDB_API_KEY = ""
SECURITYTRAILS_API_KEY = ""  # Optional for historical DNS

# Headers for API requests (only used if API checks are enabled)
VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}
ABUSE_HEADERS = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
ST_HEADERS = {"APIKEY": SECURITYTRAILS_API_KEY, "Accept": "application/json"}

# List of DNSBLs (blacklists) to check (no API required)
DNSBL_LIST = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "multi.surbl.org",
    "blacklist.woody.ch",
    "cbl.abuseat.org",
]

def is_ip(input_str):
    """Check if the input is an IP address."""
    try:
        ip_address(input_str)
        return True
    except ValueError:
        return False

def resolve_domain_to_ip(domain):
    """Resolve domain to IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def check_virustotal(input_str, is_ip_input):
    """Check reputation via VirusTotal (API required)."""
    import requests
    base_url = "https://www.virustotal.com/api/v3/"
    endpoint = "ip_addresses" if is_ip_input else "domains"
    url = f"{base_url}{endpoint}/{input_str}"
    
    try:
        response = requests.get(url, headers=VT_HEADERS)
        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            last_analysis = data["last_analysis_stats"]
            return {
                "malicious": last_analysis["malicious"],
                "suspicious": last_analysis["suspicious"],
                "harmless": last_analysis["harmless"],
                "undetected": last_analysis["undetected"]
            }
        else:
            return f"Error: {response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"

def check_abuseipdb(ip):
    """Check IP reputation via AbuseIPDB (API required)."""
    import requests
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    
    try:
        response = requests.get(url, headers=ABUSE_HEADERS)
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "abuse_confidence": data["abuseConfidenceScore"],
                "total_reports": data["totalReports"],
                "last_reported": data.get("lastReportedAt", "N/A")
            }
        else:
            return f"Error: {response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"

def check_blacklists(ip):
    """Check if IP appears on various DNS blacklists (no API required)."""
    results = {}
    reversed_ip = '.'.join(reversed(ip.split('.')))
    
    for blacklist in DNSBL_LIST:
        query = f"{reversed_ip}.{blacklist}"
        try:
            dns.resolver.resolve(query, 'A')
            results[blacklist] = "LISTED"
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            results[blacklist] = "NOT LISTED"
        except Exception as e:
            results[blacklist] = f"Error: {str(e)}"
    
    return results

def check_virustotal_historical(domain):
    """Check historical reputation via VirusTotal (API required)."""
    import requests
    from datetime import datetime
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        response = requests.get(url, headers=VT_HEADERS)
        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            last_analysis = data.get("last_analysis_stats", {})
            last_scan_date = datetime.fromtimestamp(data.get("last_analysis_date", 0)).strftime('%Y-%m-%d')
            return {
                "malicious": last_analysis.get("malicious", 0),
                "suspicious": last_analysis.get("suspicious", 0),
                "harmless": last_analysis.get("harmless", 0),
                "undetected": last_analysis.get("undetected", 0),
                "last_scan_date": last_scan_date
            }
        elif response.status_code == 404:
            return "No historical data found"
        else:
            return f"Error: {response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"

def check_passive_dns(domain):
    """Check historical DNS records via SecurityTrails (API required)."""
    import requests
    url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    try:
        response = requests.get(url, headers=ST_HEADERS)
        if response.status_code == 200:
            data = response.json()
            records = data.get("records", [])
            if not records:
                return "No historical DNS records found"
            historical_ips = []
            for record in records[:5]:  # Limit to last 5 for brevity
                ip = record.get("values", [{}])[0].get("ip", "N/A")
                first_seen = record.get("first_seen", "N/A")
                last_seen = record.get("last_seen", "N/A")
                historical_ips.append({
                    "ip": ip,
                    "first_seen": first_seen,
                    "last_seen": last_seen
                })
            return historical_ips
        else:
            return f"Error: {response.status_code}"
    except Exception as e:
        return f"Error: {str(e)}"

def analyze_target(target, no_api=False):
    """Analyze target based on whether it resolves to an IP and API usage."""
    is_ip_input = is_ip(target)
    ip_to_check = target if is_ip_input else resolve_domain_to_ip(target)
    
    print(f"\nAnalyzing: {target}")
    
    if is_ip_input or ip_to_check:  # Current IP exists
        if not is_ip_input:
            print(f"Resolved IP: {ip_to_check}")
        
        if not no_api:
            # VirusTotal Check (API)
            print("\n[VirusTotal Results]")
            vt_results = check_virustotal(target, is_ip_input)
            if isinstance(vt_results, dict):
                for key, value in vt_results.items():
                    print(f"{key.capitalize()}: {value}")
            else:
                print(vt_results)
            
            # AbuseIPDB Check (API)
            print("\n[AbuseIPDB Results]")
            abuse_results = check_abuseipdb(ip_to_check)
            if isinstance(abuse_results, dict):
                for key, value in abuse_results.items():
                    print(f"{key.replace('_', ' ').capitalize()}: {value}")
            else:
                print(abuse_results)
        
        # Blacklist Check (No API)
        print("\n[Blacklist Checks]")
        blacklist_results = check_blacklists(ip_to_check)
        for blacklist, status in blacklist_results.items():
            print(f"{blacklist}: {status}")
    
    else:  # No current IP, check historical data if APIs allowed
        if no_api:
            print("\nNo current IP resolved. Historical checks skipped (API disabled).")
        else:
            print("\nNo current IP resolved. Checking historical data...")
            
            # VirusTotal Historical Check (API)
            print("\n[VirusTotal Historical Reputation]")
            vt_hist_results = check_virustotal_historical(target)
            if isinstance(vt_hist_results, dict):
                for key, value in vt_hist_results.items():
                    print(f"{key.replace('_', ' ').capitalize()}: {value}")
            else:
                print(vt_hist_results)
            
            # Passive DNS Check (API)
            print("\n[Historical DNS Records - SecurityTrails]")
            dns_results = check_passive_dns(target)
            if isinstance(dns_results, list):
                for entry in dns_results:
                    print(f"IP: {entry['ip']}, First Seen: {entry['first_seen']}, Last Seen: {entry['last_seen']}")
            else:
                print(dns_results)

def main():
    parser = argparse.ArgumentParser(description="Check domain/IP reputation.")
    parser.add_argument("target", help="FQDN or IP to analyze")
    parser.add_argument("-n", "--no-api", action="store_true", help="Disable all API-based checks")
    args = parser.parse_args()
    
    analyze_target(args.target, args.no_api)

if __name__ == "__main__":
    main()
