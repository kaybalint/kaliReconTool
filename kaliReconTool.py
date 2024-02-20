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
    print(f'Testing {target}...\n')
    if re.match(r'[a-zA-Z]*://[\w.]*', target):
        x = target.split("//")[1]
        filename = "Scan_Results_" + x.replace('.','_').replace('/','_')
    else:
        filename = "Scan_Results_" + target.replace('.','_').replace('/','_')
    results = open(filename, 'w')
    results.write(f"Target: {target}\nStart Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    results.write("*"*20+"\n\n")
    nmapScan(target, results)
    dirbScan(target, results)
    sslScan(target, results)
    niktoScan(target, results)
    results.write(f"Scan complete.\nEnd Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}")
    results.close()
    print(f"Results are located in {filename}.")

def nmapScan(target,file):
    print("Starting Nmap scan...")
    file.write("NMAP SCAN\n")
    nk = subprocess.run(["nmap", "-p-", "-A", target], capture_output=True)
    print("Nmap scan complete.\n")
    for line in nk.stdout.decode('UTF-8').split("\n"):
        print(line)
        file.write(line+"\n")
    file.write("*"*20+"\n\n")
    #try print(f"{RED} Nmap scan failed. {ENDC}")

def niktoScan(target, file):
    print("Starting Nikto scan...")
    file.write("NIKTO SCAN\n")
    nk = subprocess.run(["nikto", "-h", target], capture_output=True)
    print("Nikto scan complete.\n")
    for line in nk.stdout.decode('UTF-8').split("\n"):
        print(line)
        file.write(line+"\n")
    file.write("*"*20+"\n\n")

def dirbScan(target, file):
    print("Starting Dirb scan...")
    file.write("DIRB SCAN\n")
    nk = subprocess.run(["dirb", "", target], capture_output=True)
    print("Dirb scan complete.\n")
    for line in nk.stdout.decode('UTF-8').split("\n"):
        print(line)
        file.write(line+"\n")
    print("*"*20+"\n\n")
    file.write("*"*20+"\n\n")

def sslScan(target, file):
    print("Starting SSL scan...")
    file.write("SSL SCAN\n")
    nk = subprocess.run(["sslscan", "", target], capture_output=True)
    print("SSL scan complete.\n")
    for line in nk.stdout.decode('UTF-8').split("\n"):
        print(line)
        file.write(line+"\n")
    print("*"*20+"\n\n")
    file.write("*"*20+"\n\n")

if __name__ == "__main__":
    main()
