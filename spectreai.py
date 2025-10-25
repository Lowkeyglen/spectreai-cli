#!/usr/bin/env python3
"""
SPECTREAI - FIXED CLI VERSION
Professional security reconnaissance tool
Zero dependencies - Pure Python power
Creator: cyberghost-ai
"""

import socket
import json
import time
import http.client
import sys
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class SpectreAICLI:
    """Ultimate CLI security reconnaissance tool"""
    
    def __init__(self, target):
        self.target = target
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'version': 'SpectreAI v1.0',
            'creator': 'cyberghost-ai',
            'findings': [],
            'risk_score': 0,
            'summary': {}
        }
    
    def print_banner(self):
        """Print awesome ASCII banner"""
        banner = """
    ╔═══════════════════════════════════════════════╗
    ║                🕵️‍♂️ SPECTREAI                 ║
    ║         AI-Powered Security Reconnaissance    ║
    ║               by cyberghost-ai                ║
    ║         Zero Dependencies • Pure Python       ║
    ╚═══════════════════════════════════════════════╝
        """
        print(banner)
    
    def comprehensive_scan(self):
        """Run complete security assessment"""
        self.print_banner()
        print(f"🎯 TARGET: {self.target}")
        print("=" * 60)
        
        # Run all scan modules with progress
        self._print_step("1", "Port Scanning", "Discovering open services")
        self.port_scan_comprehensive()
        
        self._print_step("2", "Web Analysis", "Analyzing web services")
        self.web_analysis()
        
        self._print_step("3", "Security Audit", "Checking security headers")
        self.security_headers_audit()
        
        self._print_step("4", "Risk Assessment", "Calculating risk score")
        self.risk_assessment()
        
        print("=" * 60)
        return self.generate_report()
    
    def _print_step(self, number, title, description):
        """Print formatted step"""
        print(f"\n🔹 STEP {number}: {title}")
        print(f"   📝 {description}")
    
    def port_scan_comprehensive(self):
        """Comprehensive port scanning with visual feedback"""
        ports = [
            # Web services
            80, 443, 8080, 8443, 3000, 5000,
            # Common services
            21, 22, 23, 25, 53, 110, 143, 993, 995,
            # Database services
            3306, 5432, 27017, 6379, 1433,
            # Management services
            3389, 5900, 5985, 5986,
            # Additional services
            161, 162, 389, 636, 873, 2049
        ]
        
        print(f"   🔍 Scanning {len(ports)} ports...")
        open_ports = []
        
        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    result = sock.connect_ex((self.target, port))
                    if result == 0:
                        try:
                            service = socket.getservbyport(port, 'tcp')
                        except:
                            service = 'unknown'
                        return (port, service, 'open')
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = list(executor.map(scan_port, ports))
            
            for result in results:
                if result:
                    port, service, status = result
                    open_ports.append(port)
                    finding = self._create_port_finding(port, service)
                    self.results['findings'].append(finding)
                    print(f"   ✅ Port {port}/tcp - {service}")
        
        print(f"   📊 Found {len(open_ports)} open ports")
    
    def _create_port_finding(self, port, service):
        """Create detailed port finding"""
        risk_info = self._get_port_risk(port, service)
        
        return {
            'type': 'open_port',
            'port': port,
            'service': service,
            'risk': risk_info['level'],
            'description': risk_info['description'],
            'recommendation': risk_info.get('recommendation', ''),
            'category': risk_info['category']
        }
    
    def _get_port_risk(self, port, service):
        """Get risk assessment for port/service"""
        critical_services = {
            21: {'level': 'HIGH', 'description': 'FTP - Clear text authentication', 'category': 'critical'},
            23: {'level': 'HIGH', 'description': 'Telnet - No encryption', 'category': 'critical'},
            135: {'level': 'HIGH', 'description': 'RPC - Historical vulnerabilities', 'category': 'critical'},
            139: {'level': 'HIGH', 'description': 'NetBIOS - Information disclosure', 'category': 'critical'},
            445: {'level': 'HIGH', 'description': 'SMB - Multiple vulnerabilities', 'category': 'critical'},
            3389: {'level': 'MEDIUM', 'description': 'RDP - Remote Desktop', 'category': 'management'}
        }
        
        if port in critical_services:
            return critical_services[port]
        
        if service in ['http', 'www'] and port != 443:
            return {
                'level': 'MEDIUM',
                'description': 'Unencrypted web service',
                'category': 'web',
                'recommendation': 'Enable HTTPS and redirect HTTP to HTTPS'
            }
        
        if port in [3306, 5432, 27017, 1433]:
            return {
                'level': 'MEDIUM', 
                'description': f'Database service {service}',
                'category': 'database',
                'recommendation': 'Ensure database is not publicly accessible'
            }
        
        return {
            'level': 'LOW',
            'description': f'Standard service {service}',
            'category': 'general'
        }
    
    def web_analysis(self):
        """Analyze web services"""
        web_ports = [f for f in self.results['findings'] 
                    if f['type'] == 'open_port' and f['category'] == 'web']
        
        for service in web_ports:
            self._analyze_web_service(service['port'])
    
    def _analyze_web_service(self, port):
        """Detailed web service analysis"""
        try:
            if port == 443:
                conn = http.client.HTTPSConnection(self.target, port, timeout=5)
            else:
                conn = http.client.HTTPConnection(self.target, port, timeout=5)
            
            conn.request("GET", "/")
            response = conn.getresponse()
            
            server_header = response.getheader('Server', 'Unknown')
            print(f"   🌐 Port {port}: {server_header} (HTTP {response.status})")
            
            finding = {
                'type': 'web_service',
                'port': port,
                'status_code': response.status,
                'server': server_header,
                'risk': 'LOW',
                'description': f'Web service running {server_header}',
                'category': 'web'
            }
            
            self.results['findings'].append(finding)
                    
        except Exception as e:
            print(f"   ❌ Port {port}: Web service analysis failed")
    
    def security_headers_audit(self):
        """Comprehensive security headers audit"""
        web_services = [f for f in self.results['findings'] 
                       if f['type'] == 'open_port' and f['category'] == 'web']
        
        for service in web_services:
            self._audit_security_headers(service['port'])
    
    def _audit_security_headers(self, port):
        """Audit security headers"""
        try:
            if port == 443:
                conn = http.client.HTTPSConnection(self.target, port, timeout=5)
            else:
                conn = http.client.HTTPConnection(self.target, port, timeout=5)
            
            conn.request("GET", "/")
            response = conn.getresponse()
            
            security_headers = {
                'Strict-Transport-Security': bool(response.getheader('Strict-Transport-Security')),
                'X-Frame-Options': bool(response.getheader('X-Frame-Options')),
                'X-Content-Type-Options': bool(response.getheader('X-Content-Type-Options')),
                'Content-Security-Policy': bool(response.getheader('Content-Security-Policy')),
                'X-XSS-Protection': bool(response.getheader('X-XSS-Protection'))
            }
            
            missing_headers = [h for h, present in security_headers.items() if not present]
            
            if missing_headers:
                print(f"   🛡️  Port {port}: Missing {len(missing_headers)} security headers")
                
                self.results['findings'].append({
                    'type': 'security_headers',
                    'port': port,
                    'risk': 'MEDIUM',
                    'description': f'Missing security headers: {", ".join(missing_headers)}',
                    'recommendation': 'Implement missing security headers',
                    'category': 'security'
                })
            else:
                print(f"   ✅ Port {port}: All security headers present")
                
        except Exception as e:
            print(f"   ❌ Port {port}: Security headers audit failed")
    
    def risk_assessment(self):
        """Comprehensive risk assessment"""
        risk_weights = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        
        total_risk = 0
        max_risk = 0
        
        for finding in self.results['findings']:
            weight = risk_weights.get(finding['risk'], 0)
            total_risk += weight
            max_risk += 3  # Maximum possible per finding
        
        self.results['risk_score'] = (total_risk / max_risk) * 100 if max_risk > 0 else 0
        
        # Generate summary
        self.results['summary'] = {
            'total_findings': len(self.results['findings']),
            'high_count': len([f for f in self.results['findings'] if f['risk'] == 'HIGH']),
            'medium_count': len([f for f in self.results['findings'] if f['risk'] == 'MEDIUM']),
            'low_count': len([f for f in self.results['findings'] if f['risk'] == 'LOW']),
            'open_ports': len([f for f in self.results['findings'] if f['type'] == 'open_port']),
            'web_services': len([f for f in self.results['findings'] if f['type'] == 'web_service']),
            'security_issues': len([f for f in self.results['findings'] if f['type'] == 'security_headers'])
        }
    
    def generate_report(self):
        """Generate comprehensive report"""
        filename = f"spectreai_scan_{self.target}_{int(time.time())}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Generate text report
        text_filename = f"spectreai_scan_{self.target}_{int(time.time())}.txt"
        self._generate_text_report(text_filename)
        
        return filename, text_filename
    
    def _generate_text_report(self, filename):
        """Generate human-readable text report"""
        with open(filename, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("                SPECTREAI SECURITY ASSESSMENT REPORT\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"TARGET: {self.results['target']}\n")
            f.write(f"SCAN DATE: {self.results['timestamp']}\n")
            f.write(f"RISK SCORE: {self.results['risk_score']:.1f}%\n")
            f.write(f"VERSION: {self.results['version']}\n")
            f.write(f"CREATOR: {self.results['creator']}\n\n")
            
            f.write("EXECUTIVE SUMMARY:\n")
            f.write("-" * 70 + "\n")
            f.write(f"Total Findings: {self.results['summary']['total_findings']}\n")
            f.write(f"High Risk Issues: {self.results['summary']['high_count']}\n")
            f.write(f"Medium Risk Issues: {self.results['summary']['medium_count']}\n")
            f.write(f"Low Risk Issues: {self.results['summary']['low_count']}\n")
            f.write(f"Open Ports: {self.results['summary']['open_ports']}\n")
            f.write(f"Web Services: {self.results['summary']['web_services']}\n")
            f.write(f"Security Issues: {self.results['summary']['security_issues']}\n\n")
            
            f.write("DETAILED FINDINGS:\n")
            f.write("-" * 70 + "\n")
            
            # Group by risk level
            for risk_level in ['HIGH', 'MEDIUM', 'LOW']:
                findings = [f for f in self.results['findings'] if f['risk'] == risk_level]
                if findings:
                    f.write(f"\n{risk_level} RISK FINDINGS:\n")
                    f.write("-" * 50 + "\n")
                    for finding in findings:
                        description = finding.get('description', 'No description available')
                        f.write(f"• {description}\n")
                        if finding.get('recommendation'):
                            f.write(f"  Recommendation: {finding['recommendation']}\n")
                        f.write("\n")
    
    def print_results(self):
        """Print beautiful results to console"""
        print(f"\n🎯 SCAN COMPLETED!")
        print("=" * 60)
        
        # Risk score with visual indicator
        risk_score = self.results['risk_score']
        if risk_score >= 70:
            risk_emoji = "🚨"
            risk_level = "CRITICAL"
        elif risk_score >= 40:
            risk_emoji = "⚠️"
            risk_level = "MEDIUM"
        else:
            risk_emoji = "✅"
            risk_level = "LOW"
        
        print(f"{risk_emoji} OVERALL RISK: {risk_level} ({risk_score:.1f}%)")
        
        # Statistics
        summary = self.results['summary']
        print(f"\n📊 STATISTICS:")
        print(f"   📋 Total Findings: {summary['total_findings']}")
        print(f"   🚨 High Risk: {summary['high_count']}")
        print(f"   ⚠️  Medium Risk: {summary['medium_count']}")
        print(f"   ✅ Low Risk: {summary['low_count']}")
        print(f"   🔓 Open Ports: {summary['open_ports']}")
        print(f"   🌐 Web Services: {summary['web_services']}")
        
        # Critical findings
        high_risk_findings = [f for f in self.results['findings'] if f['risk'] == 'HIGH']
        if high_risk_findings:
            print(f"\n🚨 CRITICAL FINDINGS:")
            for finding in high_risk_findings:
                description = finding.get('description', 'No description')
                print(f"   • {description}")
                if finding.get('recommendation'):
                    print(f"     💡 {finding['recommendation']}")
        
        # Medium risk findings
        medium_risk_findings = [f for f in self.results['findings'] if f['risk'] == 'MEDIUM']
        if medium_risk_findings:
            print(f"\n⚠️  MEDIUM RISK FINDINGS:")
            for finding in medium_risk_findings:
                description = finding.get('description', 'No description')
                print(f"   • {description}")
                if finding.get('recommendation'):
                    print(f"     💡 {finding['recommendation']}")

def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(description='SpectreAI - Security Reconnaissance Tool')
    parser.add_argument('target', nargs='?', help='Target domain or IP address')
    parser.add_argument('-o', '--output', help='Output filename prefix')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Get target
    if args.target:
        target = args.target
    else:
        target = input("🎯 Enter target domain or IP: ").strip()
    
    if not target:
        print("❌ No target specified")
        sys.exit(1)
    
    # Run scan
    scanner = SpectreAICLI(target)
    json_file, text_file = scanner.comprehensive_scan()
    scanner.print_results()
    
    print(f"\n📁 Reports generated:")
    print(f"   📄 JSON: {json_file}")
    print(f"   📝 Text: {text_file}")
    print(f"\n⭐ SpectreAI - Making security accessible!")
    print("   Created by cyberghost-ai")

if __name__ == "__main__":
    main()
