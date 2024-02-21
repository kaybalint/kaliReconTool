import sys
import re
import nmap
from datetime import datetime
import pytz
import subprocess

BLUE = "\033[94m"
GREEN = "\033[92m"
RED = "\033[91m"
ENDC = "\033[0m"
WRITE = False

def main():
    if len(sys.argv) == 1:
        target = input('Enter valid IPv4 or URL (including protocol): ')           
    elif len(sys.argv) == 2:
        target = sys.argv[1]
    invalid = True
    while invalid:
        if not (re.match(r'[a-zA-Z]*://[\w.]*', target) or re.match(r'[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}', target)):
            target = input('Enter valid IPv4 or URL (including protocol): ')
        else:
            invalid = False
    write = input('Would you like the results saved to a file? (y/n)')
    while write not in ('y', 'n', 'Y', 'N'):
        write = input('Would you like the results saved to a file? (y/n)')
    if write.lower() == 'y':
        WRITE = True
    print(f'\nTesting {BLUE}{target}{ENDC}...\n')
    if WRITE:
        if re.match(r'[a-zA-Z]*://[\w.]*', target):
            x = target.split("//")[1]
            filename = "Scan_Results_" + x.replace('.','_').replace('/','_')
        else:
            filename = "Scan_Results_" + target.replace('.','_').replace('/','_')
        results = open(filename, 'w')
        results.write(f"Target: {target}\nStart Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        results.write("*"*20+"\n\n")
    if re.match(r'[a-zA-Z]*://[\w.]*', target):
        domain = target.split("//")[1]
        domain_https = target
    else:
        domain = target
        domain_https = 'https://'+target
    nmapScan(domain, results)
    dirbScan(domain_https, results)
    sslScan(domain, results)
    niktoScan(domain, results)
    print(f'{GREEN}[+]{ENDC} {target} scan complete.')
    if WRITE:
        results.write(f"Scan complete.\nEnd Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}")
        results.close()
        print(f"Results are located in {filename}.")

def nmapScan(target,file):
    print("[+] Starting Nmap scan")
    file.write("NMAP SCAN\n")
    nmap_raw = subprocess.run(["nmap", "-A", target], capture_output=True)
    nmap = nmap_raw.stdout.decode('UTF-8')
    if not 'Nmap done: 0' in nmap:
        for line in nmap.split("\n"):
            print(line)
            if WRITE:
                file.write(line+"\n")
        if WRITE:
            file.write("*"*20+"\n\n")
        print(f"{GREEN}[+]{ENDC} Nmap scan successful.\n")
    else:
        print(f"{RED}[-]{ENDC} Nmap scan failed.")
        for line in nmap.split("\n"):
            print(line)

def niktoScan(target, file):
    print("[+] Starting Nikto scan")
    file.write("NIKTO SCAN\n")
    nk = subprocess.run(["nikto", "-h", target], capture_output=True)
    nikto = nk.stdout.decode('UTF-8')
    if '0 host(s)' not in nikto:
        for line in nikto.split("\n"):
            print(line)
            if WRITE:
                file.write(line+"\n")
        if WRITE:
            file.write("*"*20+"\n\n")
        print(f"{GREEN}[+]{ENDC} Nikto scan successful.\n")
    else:
        print(f"{RED}[-]{ENDC} Nikto scan failed.")
        for line in nikto.split("\n"):
            print(line)
        
def dirbScan(target, file):
    print("[+] Starting Dirb scan")
    file.write("DIRB SCAN\n")
    dirb_raw = subprocess.run(["dirb", "", target], capture_output=True)
    dirb = dirb_raw.stdout.decode('UTF-8')
    if 'FATAL' not in dirb:
        for line in dirb.split("\n"):
            print(line)
            if WRITE:
                file.write(line+"\n")
        print("*"*20+"\n\n")
        if WRITE:
            file.write("*"*20+"\n\n")        
        print(f"{GREEN}[+]{ENDC} Dirb scan successful.\n")
    else:
        print(f"{RED}[-]{ENDC} Dirb scan failed.")
        for line in dirb.split("\n"):
            print(line)

def sslScan(target, file):
    print("[+] Starting SSL scan")
    file.write("SSL SCAN\n")
    ssl_raw = subprocess.run(["sslscan", "", target], capture_output=True)
    ssl = ssl_raw.stdout.decode('UTF-8')
    if 'ERROR' not in ssl:
        for line in ssl.split("\n"):
            print(line)
            if WRITE:
                file.write(line+"\n")
        print("*"*20+"\n\n")
        if WRITE:
            file.write("*"*20+"\n\n")
        print(f"{GREEN}[+]{ENDC} SSL scan successful.\n")
    else:
        print(f"{RED}[-]{ENDC} SSL scan failed.")
        for line in ssl.split("\n"):
            print(line)

if __name__ == "__main__":
    main()
