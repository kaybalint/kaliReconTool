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
writeFile = False
file = None

def main():
    global writeFile
    global file
    if len(sys.argv) == 1:
        target = input('Enter valid IPv4 or URL (including protocol): ').strip()           
    elif len(sys.argv) == 2:
        target = sys.argv[1].strip()
    invalid = True
    while invalid:
        if not (re.match(r'[a-zA-Z]*://[\w.]*', target) or re.match(r'[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}', target)):
            target = input('Enter valid IPv4 or URL (including protocol): ').strip()
        else:
            invalid = False
    write = input('Would you like the results saved to a file? (y/n) ')
    while write not in ('y', 'n', 'Y', 'N'):
        write = input('Would you like the results saved to a file? (y/n) ')
    if write.lower() == 'y':
        writeFile = True
    print(f'\nTesting {BLUE}{target}{ENDC}...\n')
    if writeFile:
        if re.match(r'[a-zA-Z]*://[\w.]*', target):
            x = target.split("//")[1]
            filename = "Scan_Results_" + x.replace('.','_').replace('/','_')
        else:
            filename = "Scan_Results_" + target.replace('.','_').replace('/','_')
        file = open(filename, 'w')
        file.write(f"Target: {target}\nStart Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        file.write("*"*20+"\n\n")
    if re.match(r'[a-zA-Z]*://[\w.]*', target):
        domain = target.split("//")[1]
        domain_https = target + '/'
    else:
        domain = target
        domain_https = 'https://'+target+'/'
    nmapScan(domain)
    sslScan(domain)
    dirbScan(domain_https)
    niktoScan(domain)
    print(f'{GREEN}[+]{ENDC} {target} scan complete.')
    if writeFile:
        file.write(f"Scan complete.\nEnd Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}")
        file.close()
        print(f"Results are located in {filename}.")

def nmapScan(target):
    global writeFile
    global file
    print(f"{BLUE}[+]{ENDC} Starting Nmap scan")
    if writeFile: file.write("NMAP SCAN\n")
    nmap_raw = subprocess.run(["nmap", "-A", target], capture_output=True)
    nmap = nmap_raw.stdout.decode('UTF-8')
    if not 'Nmap done: 0' in nmap:
        for line in nmap.split("\n"):
            print(line)
            if writeFile:
                file.write(line+"\n")
        if writeFile:
            file.write("*"*20+"\n\n")
        print(f"{GREEN}[+]{ENDC} Nmap scan successful.\n")
    else:
        for line in nmap.split("\n"):
            print(line)
        print(f"{RED}[-]{ENDC} Nmap scan failed for {target}.\n")
        if writeFile:
            file.write(f"Nmap scan failed for {target}\n*"*20+"\n\n")

def sslScan(target):
    global writeFile
    global file
    print(f"{BLUE}[+]{ENDC} Starting SSL scan")
    if writeFile: file.write("SSL SCAN\n")
    ssl_raw = subprocess.run(["sslscan", "", target], capture_output=True)
    ssl = ssl_raw.stdout.decode('UTF-8')
    if 'ERROR' not in ssl:
        for line in ssl.split("\n"):
            print(line)
            if writeFile:
                file.write(line+"\n")
        if writeFile:
            file.write("*"*20+"\n\n")
        print(f"{GREEN}[+]{ENDC} SSL scan successful.\n")
    else:
        for line in ssl.split("\n"):
            print(line)
        print(f"{RED}[-]{ENDC} SSL scan failed for {target}.\n")
        if writeFile:
            file.write(f"SSL scan failed for {target}\n*"*20+"\n\n")
        
def dirbScan(target):
    global writeFile
    global file
    print(f"{BLUE}[+]{ENDC} Starting Dirb scan")
    if writeFile: file.write("DIRB SCAN\n")
    dirb_raw = subprocess.run(["dirb", "", target], capture_output=True)
    dirb = dirb_raw.stdout.decode('UTF-8')
    if 'FATAL' not in dirb:
        for line in dirb.split("\n"):
            print(line)
            if writeFile:
                file.write(line+"\n")
        print("*"*20+"\n\n")
        if writeFile:
            file.write("*"*20+"\n\n")        
        print(f"{GREEN}[+]{ENDC} Dirb scan successful.\n")
    else:
        for line in dirb.split("\n"):
            print(line)
        print(f"{RED}[-]{ENDC} Dirb scan failed for {target}.\n")
        if writeFile:
            file.write(f"DIRB scan failed for {target}\n*"*20+"\n\n")
        
def niktoScan(target):
    global writeFile
    global file
    print(f"{BLUE}[+]{ENDC} Starting Nikto scan")
    if writeFile: file.write("NIKTO SCAN\n")
    nk = subprocess.run(["nikto", "-h", target], capture_output=True)
    nikto = nk.stdout.decode('UTF-8')
    if '0 host(s)' not in nikto:
        for line in nikto.split("\n"):
            print(line)
            if writeFile:
                file.write(line+"\n")
        if writeFile:
            file.write("*"*20+"\n\n")
        print(f"{GREEN}[+]{ENDC} Nikto scan successful.\n")
    else:
        for line in nikto.split("\n"):
            print(line)
        print(f"{RED}[-]{ENDC} Nikto scan failed for {target}.\n")
        if writeFile:
            file.write(f"Nikto scan failed for {target}\n*"*20+"\n\n")

if __name__ == "__main__":
    main()
