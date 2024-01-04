import sys
import re
import nmap

if len(sys.argv) == 1:
    target = input('Enter target IP or URL: ')
    print(f'Testing {target}...')
elif len(sys.argv) == 2:
    if sys.argv
    print(f'Testing {sys.argv[1]}...')

nm = nmap.PortScanner()
nm.scan(host = target, arguments = "-p- -A")
print(nm.csv())
