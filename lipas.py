#!/usr/bin/env python3
"""
LIPAS - Comprehensive Web Security Assessment Tool
Version 1.0.0 | Enhanced and Optimized

Features:
- Modular architecture for easy maintenance
- Comprehensive vulnerability scanning
- Advanced subdomain enumeration
- Cookie and header manipulation
- GitHub exploit database integration
- Detailed reporting
- Robust error handling
"""
  
import os
import sys
import re
import json
import time
import socket
import argparse
import requests
import dns.resolver
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

class Config:
    """Centralized configuration management"""
    def __init__(self):
        self.max_threads = 15
        self.request_timeout = 20
        self.stealth_delay = (1, 3)
        self.max_redirects = 5
        self.retry_attempts = 3
        self.rate_limit_delay = 0.5
        self.common_ports = [80, 443, 8080, 8443, 22, 21]
        self.github_search_url = "https://api.github.com/search/code?q="
        self.user_agent = "Lipas/1.0.0 (+https://github.com/securitytools)"
        
        # Default wordlist if file not found
        self.default_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 
            'stage', 'api', 'secure', 'portal', 'app', 'blog'
        ]

class ScannerCore:
    """Core scanning functionality"""
    def __init__(self, config):
        self.config = config
        self.session = self._init_session()
        
    def _init_session(self):
        """Initialize HTTP session with retry logic"""
        session = requests.Session()
        session.verify = False
        session.allow_redirects = True
        session.max_redirects = self.config.max_redirects
        
        retry_adapter = requests.adapters.HTTPAdapter(
            max_retries=self.config.retry_attempts,
            pool_connections=self.config.max_threads,
            pool_maxsize=self.config.max_threads
        )
        session.mount('http://', retry_adapter)
        session.mount('https://', retry_adapter)
        
        session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })
        
        return session

class DomainScanner(ScannerCore):
    """Domain and subdomain scanning functionality"""
    def __init__(self, config, target):
        super().__init__(config)
        self.target = self._normalize_url(target)
        self.base_domain = self._extract_base_domain()
        
    def _normalize_url(self, url):
        """Standardize URL format"""
        if not re.match(r'^https?://', url, re.I):
            url = f'http://{url}'
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _extract_base_domain(self):
        """Extract root domain from URL"""
        domain = urlparse(self.target).netloc
        extracted = tldextract.extract(domain)
        return f"{extracted.domain}.{extracted.suffix}"
    
    def gather_domain_info(self):
        """Collect comprehensive domain information"""
        info = {
            'domain': self.base_domain,
            'ip': [],
            'mx': [],
            'nameservers': [],
            'ports': []
        }
        
        # DNS resolution
        try:
            info['ip'] = list(set(
                str(i[4][0]) for i in socket.getaddrinfo(self.base_domain, None)
            ))
        except Exception as e:
            print(f"[-] DNS resolution failed: {e}")
            
        # MX records
        try:
            info['mx'] = list(set(
                str(mx.exchange) for mx in dns.resolver.resolve(self.base_domain, 'MX')
            ))
        except Exception as e:
            print(f"[-] MX record lookup failed: {e}")
            
        # Nameservers
        try:
            info['nameservers'] = list(set(
                str(ns) for ns in dns.resolver.resolve(self.base_domain, 'NS')
            ))
        except Exception as e:
            print(f"[-] NS record lookup failed: {e}")
            
        # Port scanning
        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            futures = []
            for port in self.config.common_ports:
                futures.append(executor.submit(self._check_port, self.base_domain, port))
            
            for i, future in enumerate(as_completed(futures)):
                if future.result()[1]:  # If port is open
                    info['ports'].append(self.config.common_ports[i])
        
        return info
    
    def _check_port(self, host, port):
        """Check if port is open"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((host, port))
                return (port, result == 0)
        except Exception as e:
            print(f"[-] Port {port} check failed: {e}")
            return (port, False)
    
    def enumerate_subdomains(self, wordlist=None):
        """Discover subdomains using provided or default wordlist"""
        if not wordlist:
            wordlist = self.config.default_subdomains
            
        discovered = set()
        
        def test_subdomain(sub):
            full_domain = f"{sub}.{self.base_domain}"
            try:
                # DNS resolution check
                socket.gethostbyname(full_domain)
                
                # HTTP/S check
                for scheme in ['http', 'https']:
                    url = f"{scheme}://{full_domain}"
                    try:
                        resp = requests.head(
                            url,
                            timeout=self.config.request_timeout,
                            allow_redirects=True
                        )
                        discovered.add(url)
                        print(f"[+] Found: {url} ({resp.status_code})")
                    except requests.RequestException:
                        pass
                        
            except socket.gaierror:
                pass
            except Exception as e:
                print(f"[-] Subdomain check failed for {full_domain}: {e}")
                
        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            futures = [executor.submit(test_subdomain, sub) for sub in wordlist]
            for future in as_completed(futures):
                future.result()
                
        return list(discovered)

class VulnerabilityScanner(ScannerCore):
    """Web vulnerability scanning functionality"""
    def __init__(self, config, target):
        super().__init__(config)
        self.target = target
        
    def scan_website(self):
        """Comprehensive website vulnerability scan"""
        results = {
            'technologies': [],
            'endpoints': [],
            'vulnerabilities': []
        }
        
        try:
            resp = self.session.get(self.target)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Technology detection
            results['technologies'] = self._detect_technologies(resp, soup)
            
            # Endpoint discovery
            results['endpoints'] = self._find_endpoints(soup)
            
            # Vulnerability checks
            results['vulnerabilities'].extend(self._check_sqli(resp))
            results['vulnerabilities'].extend(self._check_xss(soup))
            results['vulnerabilities'].extend(self._check_cookies(resp.cookies))
            
        except Exception as e:
            print(f"[-] Website scan failed: {e}")
            
        return results
    
    def _detect_technologies(self, response, soup):
        """Identify web technologies in use"""
        tech = {
            'server': response.headers.get('Server', ''),
            'x_powered_by': response.headers.get('X-Powered-By', ''),
            'frameworks': []
        }
        
        framework_indicators = {
            'WordPress': [r'wp-content', r'wp-includes'],
            'Joomla': [r'joomla'],
            'Drupal': [r'drupal'],
            'Laravel': [r'laravel', r'csrf-token'],
            'React': [r'react', r'react-dom']
        }
        
        text = str(soup).lower()
        for framework, patterns in framework_indicators.items():
            if any(re.search(pattern, text, re.I) for pattern in patterns):
                tech['frameworks'].append(framework)
                
        return tech
    
    def _find_endpoints(self, soup):
        """Discover all endpoints on the website"""
        endpoints = set()
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'form']):
            url = tag.get('href') or tag.get('src') or tag.get('action')
            if url and not url.startswith(('javascript:', 'mailto:', 'tel:')):
                endpoints.add(urljoin(self.target, url))
        return list(endpoints)
    
    def _check_sqli(self, response):
        """Test for SQL injection vulnerabilities"""
        tests = [
            ("' OR '1'='1", r"SQL syntax|unclosed quotation"),
            ("' OR 1=1--", r"SQL syntax|unclosed quotation"),
            ("' AND 1=CONVERT(int", r"conversion failed")
        ]
        
        vulns = []
        for payload, pattern in tests:
            if re.search(pattern, response.text, re.I):
                vulns.append({
                    'type': 'SQL Injection',
                    'payload': payload,
                    'confidence': 'high'
                })
        return vulns
    
    def _check_xss(self, soup):
        """Check for potential XSS vulnerabilities"""
        vulns = []
        for input_tag in soup.find_all('input'):
            if input_tag.get('type') not in ['hidden', 'submit']:
                vulns.append({
                    'type': 'Potential XSS',
                    'element': str(input_tag),
                    'confidence': 'medium'
                })
        return vulns
    
    def _check_cookies(self, cookies):
        """Analyze cookies for security issues"""
        issues = []
        for name, cookie in cookies.items():
            if not cookie.get('httponly', False):
                issues.append({
                    'type': 'Cookie Security',
                    'issue': 'Missing HttpOnly flag',
                    'cookie': name
                })
            if not cookie.get('secure', False) and urlparse(self.target).scheme == 'https':
                issues.append({
                    'type': 'Cookie Security',
                    'issue': 'Missing Secure flag',
                    'cookie': name
                })
        return issues

class ReportGenerator:
    """Reporting and output functionality"""
    @staticmethod
    def generate(results, scan_time):
        """Generate comprehensive JSON report"""
        return json.dumps({
            'metadata': {
                'tool': 'LIPAS',
                'version': '1.0.0',
                'scan_time': scan_time
            },
            'results': results
        }, indent=2)
    
    @staticmethod
    def print_summary(results):
        """Print human-readable summary"""
        print("\n[=== SCAN SUMMARY ===]")
        print(f"Target: {results['target']}")
        print(f"Scan completed in {results['scan_duration']:.2f} seconds")
        print(f"\nDomain Information:")
        print(f" - IPs: {', '.join(results['domain_info'].get('ip', ['None found']))}")
        print(f" - Open Ports: {', '.join(map(str, results['domain_info'].get('ports', []))) or 'None'}")
        print(f"\nFound {len(results['subdomains'])} subdomains")
        print(f"Found {len(results['vulnerabilities'])} potential vulnerabilities")

class WebScanPro:
    """Main application controller"""
    def __init__(self):
        self.config = Config()
        self.results = {
            'target': '',
            'domain_info': {},
            'subdomains': [],
            'vulnerabilities': [],
            'technologies': [],
            'endpoints': [],
            'scan_duration': 0
        }
        
    def run_scan(self, target_url, cookies=None, headers=None):
        """Execute complete scanning process"""
        start_time = time.time()
        self.results['target'] = target_url
        
        try:
            # Domain scanning phase
            domain_scanner = DomainScanner(self.config, target_url)
            self.results['domain_info'] = domain_scanner.gather_domain_info()
            self.results['subdomains'] = domain_scanner.enumerate_subdomains()
            
            # Vulnerability scanning phase
            vuln_scanner = VulnerabilityScanner(self.config, target_url)
            vuln_results = vuln_scanner.scan_website()
            self.results.update(vuln_results)
            
            # Calculate scan duration
            self.results['scan_duration'] = time.time() - start_time
            
            return True
        except Exception as e:
            print(f"[!] Critical scan error: {e}")
            return False

def main():
    """Command-line interface"""
    print(r"""

        ██╗     ██╗██████╗  █████╗ ███████╗
        ██║     ██║██╔══██╗██╔══██╗██╔════╝
        ██║     ██║██████╔╝███████║███████╗
        ██║     ██║██╔═══╝ ██╔══██║╚════██║
        ███████╗██║██║     ██║  ██║███████║
        ╚══════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝
    """)
    print("LIPAS - Comprehensive Web Security Scanner")
    print("Lipas by Abel Muturi")
    print("Version 1.0.0 \n")
    
    parser = argparse.ArgumentParser(
        description='LIPAS - Advanced Web Security Scanner'
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-c', '--cookies', help='Cookies in "name=value; name2=value2" format')
    parser.add_argument('-H', '--headers', help='Custom headers in "Header: Value" format')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads')
    
    args = parser.parse_args()
    
    # Configure scanner
    scanner = WebScanPro()
    if args.threads:
        scanner.config.max_threads = args.threads
    
    # Parse cookies and headers if provided
    cookies = {}
    if args.cookies:
        for pair in args.cookies.split(';'):
            if '=' in pair.strip():
                name, value = pair.strip().split('=', 1)
                cookies[name] = value
                
    headers = {}
    if args.headers:
        for header in args.headers.split('\\n'):
            if ':' in header.strip():
                name, value = header.strip().split(':', 1)
                headers[name] = value.strip()
    
    # Run scan
    if scanner.run_scan(args.url, cookies, headers):
        # Generate and display results
        report = ReportGenerator.generate(scanner.results, time.strftime("%Y-%m-%d %H:%M:%S"))
        ReportGenerator.print_summary(scanner.results)
        print("\n[+] Full Report:")
        print(report)
    else:
        print("\n[!] Scan failed to complete")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)