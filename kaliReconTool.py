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

    print(f'Testing {target}...\n')
    if re.match(r'[a-zA-Z]*://[\w.]*', target):
        x = target.split("//")[1]
        filename = "Scan_Results_" + x.replace('.','_').replace('/','_')
    else:
        filename = "Scan_Results_" + target.replace('.','_').replace('/','_')
    results = open(filename, 'w')
    results.write(f"Target: {target}\nStart Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    results.write("*"*20+"\n")
    nmapScan(target, results)
    niktoScan(target, results)
    results.write(f"Scan complete.\nEnd Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}")
    results.close()
    print(f"Results are located in {filename}.")

def nmapScan(target, file):
    print("Starting Nmap scan...")
    file.write(f"NMAP SCAN\nStart Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}\n")
    nm = nmap.PortScanner()
    nm.scan(hosts = target, arguments = "-p- -A")
    print("Nmap scan complete.\n")
    file.write(f"End Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    for host in nm.all_hosts():
        file.write(f"Host: {host} ({nm[host].hostname()})\n")
        file.write(f"State: {nm[host].state()}\n----------\n")
        for protocol in nm[host].all_protocols():
               file.write(f"Protocol: {protocol}\n")
               for port in nm[host][protocol].keys():
                   file.write(f"Port: {port}\t")
                   for data in nm[host][protocol][port].keys():
                       x = nm[host][protocol][port][data]
                       if x:
                           file.write(f"{data.capitalize()}: {x}\t")
                       else:
                           file.write(f"{data.capitalize()}: N/A\t")
                   file.write("\n")
    file.write("*"*20+"\n")

def niktoScan(target, file):
    print("Starting nikto scan...")
    nk = subprocess.run(["nikto", "-h", target], capture_output=True)
    for line in str(nk.stdout).split("\n")
        file.write(line)
    print("Nikto scan complete.\n")

if __name__ == "__main__":
    main()
