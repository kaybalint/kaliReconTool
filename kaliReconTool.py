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

def main():
    if len(sys.argv) == 1:
        target = input('Enter target IP or URL: ')           
    elif len(sys.argv) == 2:
        target = sys.argv[1]
##    invalid = True
##    while invalid:
##        if not (re.match(r'[a-zA-Z]*://[\w.]*', target) or re.match(r'[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}', target)):
##            target = input('Enter valid IPv4 or URL (including protocol): ')
##        else:
##            invalid = False
    print(f'Testing {BLUE}{target}{ENDC}...\n')
    if re.match(r'[a-zA-Z]*://[\w.]*', target):
        x = target.split("//")[1]
        filename = "Scan_Results_" + x.replace('.','_').replace('/','_')
    else:
        filename = "Scan_Results_" + target.replace('.','_').replace('/','_')
    results = open(filename, 'w')
    results.write(f"Target: {target}\nStart Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    results.write("*"*20+"\n\n")
    nmapScan(target, results)
    #dirbScan(target, results)
    #sslScan(target, results)
    #niktoScan(target, results)
    results.write(f"Scan complete.\nEnd Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}")
    results.close()
    print(f"Results are located in {filename}.")

def nmapScan(target,file):
    print("[+] Starting Nmap scan")
    file.write("NMAP SCAN\n")
    nmap_raw = subprocess.run(["nmap", "-p-", "-A", target], capture_output=True)
    nmap = nmap_raw.stdout.decode('UTF-8')
    if not nmap.contains('Nmap done: 0'):
        for line in nmap.split("\n"):
            print(line)
            file.write(line+"\n")
        file.write("*"*20+"\n\n")
        print(f"{GREEN}[+]{ENDC} Nmap scan successful.")
    else:
        print(f"{RED}[-]{ENDC} Nmap scan failed.")

def niktoScan(target, file):
    print("[+] Starting Nikto scan")
    file.write("NIKTO SCAN\n")
    nk = subprocess.run(["nikto", "-h", target], capture_output=True)
    if nk:
        for line in nk.stdout.decode('UTF-8').split("\n"):
            print(line)
            file.write(line+"\n")
        file.write("*"*20+"\n\n")
        print(f"{GREEN}[+]{ENDC} Nikto scan complete.\n")
    else:
        print(f"{RED}[-]{ENDC} Nikto scan failed.")
        
def dirbScan(target, file):
    print("[+] Starting Dirb scan")
    file.write("DIRB SCAN\n")
    dirb = subprocess.run(["dirb", "", target], capture_output=True)
    if dirb:
        for line in dirb.stdout.decode('UTF-8').split("\n"):
            print(line)
            file.write(line+"\n")
        print("*"*20+"\n\n")
        file.write("*"*20+"\n\n")        
        print(f"{GREEN}[+]{ENDC} Dirb scan complete.\n")
    else:
        print(f"{RED}[-]{ENDC} Dirb scan failed.")

def sslScan(target, file):
    print("[+] Starting SSL scan")
    file.write("SSL SCAN\n")
    ssl = subprocess.run(["sslscan", "", target], capture_output=True)
    if ssl:
        for line in ssl.stdout.decode('UTF-8').split("\n"):
            print(line)
            file.write(line+"\n")
        print("*"*20+"\n\n")
        file.write("*"*20+"\n\n")
        print(f"{GREEN}[+]{ENDC} SSL scan complete.\n")
    else:
        print(f"{RED}[-]{ENDC} SSL scan failed.")

if __name__ == "__main__":
    main()
