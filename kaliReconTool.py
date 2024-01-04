import sys

if len(sys.argv) == 0:
    ip = input('Enter IP address: ')
    print(f'Testing {ip}...')
elif len(sys.argv) == 1:
    print(f'Testing {sys.argv[0]}...')
