import socket
import requests
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
from colorama import init, Fore, Back, Style
import json
import re
import ssl
from urllib.parse import urlparse
import time
import urllib3
import os
from datetime import datetime

# تعطيل تحذيرات HTTPS غير الموثوقة
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# Telegram channel link
print(f"\n{Fore.CYAN}Join my Telegram channel: {Fore.YELLOW}https://t.me/Android_Ghosts")
print(f"{Fore.CYAN}Ultimate Subdomain & CDN Discovery Tool\n{'-'*60}")

# Extended list of potential subdomains
EXTENDED_SUB_LIST = [
    
]

# Reliable Certificate Transparency Logs
CT_LOGS = [
    "https://crt.sh/?q={}&output=json",
    "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
    "https://sslmate.com/certspotter/api/v1/issuances?domain={}"
]

# CDN detection patterns
CDN_PROVIDERS = {
    'Cloudflare': ['cloudflare', 'cf-'],
    'CloudFront': ['cloudfront', 'awsdns'],
    'Akamai': ['akamai', 'akamaiedge', 'akamaihd'],
    'Fastly': ['fastly', 'fastly.net'],
    'Incapsula': ['incapdns'],
    'Azure CDN': ['azureedge'],
    'Google Cloud CDN': ['googleusercontent', 'c.documentcloud'],
    'Sucuri': ['sucuri'],
    'StackPath': ['stackpathdns'],
    'Imperva': ['imperva'],
    'OVH CDN': ['cdn.ovh.net'],
    'BunnyCDN': ['b-cdn.net'],
    'KeyCDN': ['kxcdn.com'],
    'CDN77': ['cdn77.org'],
    'Limelight': ['llnwd.net'],
    'EdgeCast': ['edgecastcdn.net']
}

# Create session with common settings
SESSION = requests.Session()
SESSION.verify = False
SESSION.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive'
})

def get_ssl_cert_info(hostname):
    """Get SSL certificate information using built-in ssl module"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Parse subject
                subject = {}
                if cert and 'subject' in cert:
                    for item in cert['subject']:
                        for key, value in item:
                            subject[key] = value
                
                # Parse issuer
                issuer = {}
                if cert and 'issuer' in cert:
                    for item in cert['issuer']:
                        for key, value in item:
                            issuer[key] = value
                
                return {
                    'subject': subject,
                    'issuer': issuer,
                    'expiry': cert.get('notAfter', '') if cert else '',
                    'SANs': []
                }
    except Exception as e:
        print(f"{Fore.YELLOW}[!] SSL Cert Error for {hostname}: {e}")
        return None

def get_tls_info(hostname):
    """Get TLS protocol and cipher suite information"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                protocol = ssock.version()
                cert = ssock.getpeercert()
                
                subject = {}
                if cert and 'subject' in cert:
                    for item in cert['subject']:
                        for key, value in item:
                            subject[key] = value
                
                return {
                    'protocol': protocol,
                    'cipher_suite': cipher[0] if cipher else 'Unknown',
                    'peer_principal': subject.get('commonName', '')
                }
    except Exception as e:
        print(f"{Fore.YELLOW}[!] TLS Info Error for {hostname}: {e}")
        return None

def get_http_headers(url):
    """Get HTTP headers for a URL"""
    try:
        if not url.startswith('http'):
            url = f"https://{url}"
        
        response = SESSION.head(url, timeout=10, allow_redirects=True)
        return dict(response.headers)
    except requests.exceptions.RequestException as e:
        print(f"{Fore.YELLOW}[!] HTTP Headers Error for {url}: {str(e)}")
        return {}
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Unexpected HTTP Headers Error for {url}: {str(e)}")
        return {}

def detect_cdn(hostname):
    """Advanced CDN detection using multiple methods"""
    cdn_info = {
        'provider': None,
        'cname': None,
        'ip_ranges': [],
        'headers': {}
    }

    try:
        # Method 1: Check CNAME records
        try:
            answers = dns.resolver.resolve(hostname, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target).lower()
                cdn_info['cname'] = cname
                for provider, patterns in CDN_PROVIDERS.items():
                    for pattern in patterns:
                        if pattern.lower() in cname:
                            cdn_info['provider'] = provider
                            return cdn_info
        except:
            pass

        # Method 2: Check IP address
        try:
            ip = socket.gethostbyname(hostname)
            cdn_info['ip_ranges'].append(ip)
            for provider, patterns in CDN_PROVIDERS.items():
                for pattern in patterns:
                    if pattern.lower() in ip.lower():
                        cdn_info['provider'] = provider
                        return cdn_info
        except:
            pass

        # Method 3: Check HTTP headers
        headers = get_http_headers(hostname)
        cdn_info['headers'] = headers
        
        for provider, patterns in CDN_PROVIDERS.items():
            for pattern in patterns:
                for header, value in headers.items():
                    if pattern.lower() in str(value).lower():
                        cdn_info['provider'] = provider
                        return cdn_info

    except Exception as e:
        print(f"{Fore.YELLOW}[!] CDN detection error for {hostname}: {e}")

    return cdn_info

def find_linked_assets(hostname):
    """Find linked assets (JS, CSS, images) from a hostname"""
    linked_assets = set()
    try:
        if not hostname.startswith('http'):
            url = f"https://{hostname}"
        else:
            url = hostname

        response = SESSION.get(url, timeout=15)
        content = response.text

        # Find all external resources
        patterns = [
            r'src=["\'](https?://[^"\']+)["\']',
            r'href=["\'](https?://[^"\']+)["\']',
            r'url\(["\']?(https?://[^"\')]+)["\']?\)',
            r'content=["\'](https?://[^"\']+)["\']'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                parsed = urlparse(match)
                if parsed.netloc and parsed.netloc != hostname:
                    linked_assets.add(parsed.netloc)

    except requests.exceptions.RequestException as e:
        print(f"{Fore.YELLOW}[!] Request Error finding linked assets for {hostname}: {str(e)}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Unexpected Error finding linked assets for {hostname}: {str(e)}")

    return linked_assets

def analyze_host(hostname):
    """Perform comprehensive analysis of a host"""
    result = {
        'hostname': hostname,
        'ip': None,
        'tls_info': None,
        'http_headers': None,
        'cdn': None,
        'linked_assets': [],
        'timestamp': datetime.now().isoformat()
    }

    try:
        # Get IP address
        result['ip'] = socket.gethostbyname(hostname)
        
        # Get TLS information
        result['tls_info'] = get_tls_info(hostname)
        
        # Get HTTP headers
        result['http_headers'] = get_http_headers(hostname)
        
        # Detect CDN
        result['cdn'] = detect_cdn(hostname)
        
        # Find linked assets
        result['linked_assets'] = list(find_linked_assets(hostname))
        
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error analyzing {hostname}: {e}")
    
    return result

def print_host_report(host_info):
    """Print detailed report for a single host"""
    print(f"\n{Fore.BLUE}{Style.BRIGHT}.TARGET --> https://{host_info['hostname']}")
    
    if host_info['ip']:
        print(f"{Fore.GREEN}[+] IP Address: {host_info['ip']}")
    
    if host_info['tls_info']:
        print(f"{Fore.CYAN}[*] CipherSuite: {host_info['tls_info']['cipher_suite']}")
        print(f"{Fore.CYAN}[*] Protocol: {host_info['tls_info']['protocol']}")
        if host_info['tls_info']['peer_principal']:
            print(f"{Fore.CYAN}[*] PeerPrincipalCN: {host_info['tls_info']['peer_principal']}")
    
    if host_info['http_headers']:
        print(f"{Fore.MAGENTA}{'-'*25} HTTP Headers {'-'*25}")
        for header, value in host_info['http_headers'].items():
            print(f"{Fore.YELLOW}{header}: {Fore.WHITE}{value}")
    
    if host_info['cdn'] or host_info['linked_assets']:
        print(f"{Fore.GREEN}{'-'*25} CDN & Linked Assets {'-'*25}")
        
        if host_info['cdn'] and host_info['cdn']['provider']:
            print(f"{Fore.CYAN}[+] CDN Provider: {Fore.WHITE}{host_info['cdn']['provider']}")
            if host_info['cdn']['cname']:
                print(f"{Fore.CYAN}[+] CNAME: {Fore.WHITE}{host_info['cdn']['cname']}")
        
        # Print linked assets with their CDN info
        if host_info['linked_assets']:
            print(f"\n{Fore.MAGENTA}[*] Linked External Assets:")
            for asset in host_info['linked_assets']:
                asset_cdn = detect_cdn(asset)
                if asset_cdn['provider']:
                    print(f"{Fore.GREEN}[+] {asset} ({asset_cdn['provider']})")
                    try:
                        asset_ips = socket.gethostbyname_ex(asset)[2]
                        for ip in asset_ips:
                            print(f"{Fore.YELLOW}    ==> {ip}")
                    except:
                        pass
                else:
                    print(f"{Fore.YELLOW}[-] {asset} (No CDN detected)")
        print(f"{Fore.GREEN}{'-'*20} END CDN & Assets {'-'*20}")

def check_subdomain(subdomain, domain):
    """Check a specific subdomain with comprehensive analysis"""
    full_domain = f"{subdomain}.{domain}"
    try:
        print(f"{Fore.BLUE}[*] Checking {full_domain}...")
        host_info = analyze_host(full_domain)
        if host_info['ip']:
            print_host_report(host_info)
            return host_info
        else:
            print(f"{Fore.RED}[-] {full_domain} → Not available")
            return None
    except (socket.gaierror, socket.timeout):
        print(f"{Fore.RED}[-] {full_domain} → Not available")
        return None
    except Exception as e:
        print(f"{Fore.RED}[!] {full_domain} → Error: {str(e)}")
        return None

def dns_enumeration(domain, max_workers=50):
    """Search for subdomains via DNS with comprehensive analysis"""
    found_subdomains = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for sub in EXTENDED_SUB_LIST:
            futures.append(executor.submit(check_subdomain, sub, domain))
        
        for future in futures:
            result = future.result()
            if result:
                found_subdomains.append(result)
    
    return found_subdomains

def query_ct_log(url, domain):
    """Query a single Certificate Transparency log"""
    try:
        formatted_url = url.format(domain)
        response = SESSION.get(formatted_url, timeout=30)
        
        if response.status_code == 200:
            if 'crt.sh' in url:
                data = response.json()
                return [item['name_value'].lower().strip() for item in data if domain in item['name_value']]
            elif 'certspotter' in url or 'sslmate' in url:
                data = response.json()
                subdomains = []
                for item in data:
                    for name in item.get('dns_names', []):
                        if domain in name:
                            subdomains.append(name.lower().strip())
                return subdomains
    except requests.exceptions.RequestException as e:
        print(f"{Fore.YELLOW}[!] Request Error querying {url}: {str(e)}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Unexpected Error querying {url}: {str(e)}")
    return []

def certificate_transparency_search(domain):
    """Search through multiple Certificate Transparency logs"""
    all_subdomains = set()
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(query_ct_log, url, domain) for url in CT_LOGS]
        
        for future in futures:
            try:
                subdomains = future.result()
                for sub in subdomains:
                    # Clean and normalize the subdomains
                    sub = sub.lower().strip()
                    sub = re.sub(r'^\.', '', sub)  # Remove leading dots
                    sub = re.sub(r'^\*\.', '', sub)  # Remove wildcards
                    if domain in sub:
                        all_subdomains.add(sub)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error processing CT results: {e}")
    
    return sorted(all_subdomains)

def save_results(domain, results):
    """Save results to multiple files with different formats"""
    if not results:
        print(f"{Fore.RED}[-] No results to save!")
        return
    
    # Create results directory if not exists
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dir_name = f"scan_results_{domain}_{timestamp}"
    os.makedirs(dir_name, exist_ok=True)
    
    # 1. Save full JSON report
    json_filename = os.path.join(dir_name, f"full_report.json")
    with open(json_filename, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n{Fore.CYAN}[*] Full JSON report saved to: {json_filename}")
    
    # 2. Save simple text report
    txt_filename = os.path.join(dir_name, f"simple_report.txt")
    with open(txt_filename, 'w') as f:
        for item in results:
            f.write(f"\n.TARGET --> https://{item['hostname']}\n")
            
            if item['ip']:
                f.write(f"[+] IP: {item['ip']}\n")
            
            if item['tls_info']:
                f.write(f"[*] CipherSuite: {item['tls_info']['cipher_suite']}\n")
                f.write(f"[*] Protocol: {item['tls_info']['protocol']}\n")
                if item['tls_info']['peer_principal']:
                    f.write(f"[*] PeerPrincipalCN: {item['tls_info']['peer_principal']}\n")
            
            if item['cdn'] and item['cdn']['provider']:
                f.write(f"[+] CDN Provider: {item['cdn']['provider']}\n")
                if item['cdn']['cname']:
                    f.write(f"[+] CNAME: {item['cdn']['cname']}\n")
            
            if item['linked_assets']:
                f.write("\n[*] Linked External Assets:\n")
                for asset in item['linked_assets']:
                    asset_cdn = detect_cdn(asset)
                    if asset_cdn['provider']:
                        f.write(f"[+] {asset} ({asset_cdn['provider']})\n")
                    else:
                        f.write(f"[-] {asset} (No CDN detected)\n")
            f.write("\n" + "="*80 + "\n")
    print(f"{Fore.CYAN}[*] Simple text report saved to: {txt_filename}")
    
    # 3. Save all discovered subdomains
    subs_filename = os.path.join(dir_name, f"subdomains.txt")
    with open(subs_filename, 'w') as f:
        for item in results:
            f.write(f"{item['hostname']}\n")
    print(f"{Fore.CYAN}[*] Subdomains list saved to: {subs_filename}")
    
    # 4. Save CDN information separately
    cdn_filename = os.path.join(dir_name, f"cdn_info.txt")
    with open(cdn_filename, 'w') as f:
        for item in results:
            if item['cdn'] and item['cdn']['provider']:
                f.write(f"Hostname: {item['hostname']}\n")
                f.write(f"Provider: {item['cdn']['provider']}\n")
                if item['cdn']['cname']:
                    f.write(f"CNAME: {item['cdn']['cname']}\n")
                if item['ip']:
                    f.write(f"IP: {item['ip']}\n")
                f.write("\n")
    print(f"{Fore.CYAN}[*] CDN information saved to: {cdn_filename}")

def main():
    print(f"{Fore.BLUE}{Back.WHITE}{Style.BRIGHT}=== Advanced Subdomain & CDN Discovery Tool ===")
    domain = input(f"{Fore.YELLOW}[?] Enter domain to scan (e.g. example.com): ").strip().lower()
    
    if not domain:
        print(f"{Fore.RED}[-] No domain provided. Exiting...")
        return
    
    # Check main domain first
    print(f"\n{Fore.BLUE}[*] Analyzing main domain...")
    main_host_info = analyze_host(domain)
    if main_host_info:
        print_host_report(main_host_info)
    
    all_results = [main_host_info] if main_host_info else []
    
    print(f"\n{Fore.BLUE}[*] Starting subdomain search...")
    
    # DNS search
    print(f"\n{Fore.MAGENTA}[1] Searching via DNS...")
    dns_results = dns_enumeration(domain)
    all_results.extend([r for r in dns_results if r])
    
    # Certificate Transparency search
    print(f"\n{Fore.MAGENTA}[2] Searching via Certificate Transparency logs...")
    cert_subs = certificate_transparency_search(domain)
    
    # Verify CT results
    print(f"\n{Fore.MAGENTA}[3] Verifying discovered subdomains...")
    existing_hostnames = [r['hostname'] for r in all_results]
    for sub in cert_subs:
        if sub not in existing_hostnames:
            try:
                print(f"{Fore.BLUE}[*] Checking {sub}...")
                result = analyze_host(sub)
                if result and result['ip']:
                    print_host_report(result)
                    all_results.append(result)
                else:
                    print(f"{Fore.RED}[-] {sub} → Not available")
            except Exception as e:
                print(f"{Fore.RED}[!] Error processing {sub}: {e}")

    # Save results
    if all_results:
        save_results(domain, all_results)
        print(f"\n{Fore.GREEN}{Style.BRIGHT}[+] Scan completed successfully!")
    else:
        print(f"\n{Fore.RED}{Style.BRIGHT}[-] No valid subdomains found!")

if __name__ == "__main__":
    try:
        import dns.resolver
    except ImportError:
        print(f"{Fore.YELLOW}[!] Warning: dnspython library not found. Some features may not work.")
        print(f"{Fore.YELLOW}[!] Install with: pip install dnspython")
    
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-] Program stopped by user")
    except Exception as e:
        print(f"\n{Fore.RED}[-] Unexpected error: {str(e)}")
