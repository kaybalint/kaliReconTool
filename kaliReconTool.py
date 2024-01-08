import sys
import re
import nmap
from datetime import datetime
import pytz
import subprocess

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
    testNmap(target, results)
    dirbScan(target, results)
    sslScan(target, results)
    niktoScan(target, results)
    results.write(f"Scan complete.\nEnd Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}")
    results.close()
    print(f"Results are located in {filename}.")

def testNmap(target,file):
    print("Starting Nmap scan...")
    file.write("NMAP SCAN\n")
    nk = subprocess.run(["nmap", "-p- -A", target], capture_output=True)
    print("Nmap scan complete.\n")
    for line in nk.stdout.decode('UTF-8').split("\n"):
        print(line)
        file.write(line+"\n")
    file.write("*"*20+"\n\n")

def nmapScan(target, file):
    print("Starting Nmap scan...")
    print(f"Start Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}\n")
    file.write(f"NMAP SCAN\nStart Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}\n")
    nm = nmap.PortScanner()
    nm.scan(hosts = target, arguments = "-p- -A")
    print("Nmap scan complete.\n")
    print(f"End Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    file.write(f"End Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})\n")
        file.write(f"Host: {host} ({nm[host].hostname()})\n")
        print(f"State: {nm[host].state()}\n----------\n")
        file.write(f"State: {nm[host].state()}\n----------\n")
        for protocol in nm[host].all_protocols():
            print(f"Protocol: {protocol}\n")
            file.write(f"Protocol: {protocol}\n")
            for port in nm[host][protocol].keys():
                print(f"Port: {port}", end='\t')
                file.write(f"Port: {port}\t")
                for data in nm[host][protocol][port].keys():
                    data = data.strip()
                    x = nm[host][protocol][port][data]
                    if x:
                        if data in ['port', 'state', 'name', 'product', 'version']:
                            print(f"{data.capitalize()}: {x}", end='\t')
                            file.write(f"{data.capitalize()}: {x}\t")
                        else:
                            file.write(f"{data.capitalize()}: {x}\t")
                    else:
                        print(f"{data.capitalize()}: N/A", end='\t')
                        file.write(f"{data.capitalize()}: N/A\t")
                print()
                file.write("\n")
        print()        
        file.write("\n")
    print("*"*20+"\n\n")    
    file.write("*"*20+"\n\n")

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
