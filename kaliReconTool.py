import sys
import re
import nmap

if len(sys.argv) == 1:
    target = input('Enter target IP or URL: ')
    
elif len(sys.argv) == 2:
    target = sys.argv[1]

print(f'Testing {target}...')
nm = nmap.PortScanner()
nm.scan(hosts = target, arguments = "-p- -A")
print(nm.csv())
