import sys
import re
import nmap

def main():
    if len(sys.argv) == 1:
        target = input('Enter target IP or URL: ')
        
    elif len(sys.argv) == 2:
        target = sys.argv[1]

    print(f'Testing {target}...')
    filename = "Scan Results for " + target + ".txt"
    results = open(filename, 'w')
    results.write(f"Target: {target}\n")
    results.write("*"*20+"\n")
    nmap = nmapScan(target)
    addToFile("Nmap scan", results, nmap)
    results.close()
    print(f"Results are located in {filename}.")

def nmapScan(target):
    print("Starting Nmap scan...")
    nm = nmap.PortScanner()
    nm.scan(hosts = target, arguments = "-p- -A")
    print("Nmap scan complete.")
    return nm.csv()
    
def addToFile(scan, file, results):
    file.write(scan+"\n")
    file.write(results)
    file.write("*"*20)

if __name__ == "__main__":
    main()
