import sys
import re
import nmap

def main():
    if len(sys.argv) == 1:
        target = input('Enter target IP or URL: ')
        
    elif len(sys.argv) == 2:
        target = sys.argv[1]

    print(f'Testing {target}...')
    filename = "Scan Results for " + target
    results = open(filename, 'w')

    nm = nmap.PortScanner()
    nm.scan(hosts = target, arguments = "-p- -A")
    addToFile("Nmap scan", results, nm.csv())
    print("Nmap scan complete...")

    results.close()
    print(f"Results are located in {filename}.")


def addToFile(scan, file, results):
    file.write(scan)
    file.write(results)
    file.write("*"*10)

if __name__ == "__main__":
    main()
