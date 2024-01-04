import sys
import re
import nmap

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
    results.write(f"Target: {target}\n\n")
    results.write("*"*20+"\n")
    nmap = nmapScan(target)
    addToFile("NMAP SCAN", results, nmap)
    results.close()
    print(f"Results are located in {filename}.")

def nmapScan(target):
    print("Starting Nmap scan...")
    nm = nmap.PortScanner()
    nm.scan(hosts = target, arguments = "-p- -A")
    print("Nmap scan complete.")
    data = nm.csv()
    nmapData = ""
    for line in data.split("\n"):
        nmapData+=line.replace(";","\t|\t")+"\n"
    return nmapData
    
def addToFile(scan, file, results):
    file.write(scan+"\n\n")
    file.write(results+"\n")
    file.write("*"*20+"\n")

if __name__ == "__main__":
    main()
