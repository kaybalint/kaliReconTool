import sys
import re
import nmap
from datetime import datetime
import pytz

def main():
    if len(sys.argv) == 1:
        target = input('Enter target IP or URL: ')
        
    elif len(sys.argv) == 2:
        target = sys.argv[1]

    print(f'Testing {target}...')
    if re.match(r'[a-zA-Z]*://[\w.]*', target):
        hostname = target.split("//")[1]
        if hostname[-1]=="/":
            hostname=hostname[:-1]
        filename = "Scan_Results_" + hostname.replace('.','_')
        print(filename)
    else:
        filename = "Scan_Results_" + target
    results = open(filename, 'w')
    results.write(f"Target: {target}\nStart Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    results.write("*"*20+"\n")
    nmap = nmapScan(target, results)
    results.write(f"Scan complete.\nEnd Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}")
    results.close()
    print(f"Results are located in {filename}.")

def nmapScan(target, file):
    print("Starting Nmap scan...")
    file.write(f"NMAP SCAN\nStart Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}\n")
    nm = nmap.PortScanner()
    nm.scan(hosts = target, arguments = "-p- -A")
    print("Nmap scan complete.")
    file.write(f"End Time: {datetime.now(pytz.timezone('America/New_York')).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    for host in nm.all_hosts():
        file.write(f"Host: {host} ({nm[host].hostname()})\n")
        file.write(f"State: {nm[host].state()}\n----------\n")
        for protocol in nm[host].all_protocols():
               file.write(f"Protocol: {protocol}\n")
               for port in nm[host][protocol].keys():
                   file.write(f"Port: {port}\t")
                    for data in nm[host][protocol][host].keys():
                        x = nm[host][protocol][port][data]
                        if x:
                            file.write(f"{data}: {x}\t")
                        else:
                            file.write(f"{data}: N/A\t")
                        #Name: {nm[host][protocol][port]['name']}\tState: {nm[host][protocol][port]['state']}\tProduct: {nm[host][protocol][port]['product']}\tExtra Info: {nm[host][protocol][port]['extrainfo']}\tReason: {nm[host][protocol][port]['reason']}\tVersion: {nm[host][protocol][port]['version']}\n")
    file.write("*"*20+"\n")
    
def addToFile(scan, file, results):
    file.write(scan+"\n\n")
    file.write(results)
    file.write("*"*20+"\n")

if __name__ == "__main__":
    main()
