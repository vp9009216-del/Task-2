# Task-2
import socket

target = "127.0.0.1"
ports = [21, 22, 80, 443]

for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)

    result = s.connect_ex((target, port))
    if result == 0:
        print(f"Port {port} is OPEN")
    else:
        print(f"Port {port} is CLOSED")

    s.close()import socket

target = "127.0.0.1"

for port in range(1, 1025):
    s = socket.socket()
    s.settimeout(0.5)
    if s.connect_ex((target, port)) == 0:
        print("Open port:", port)
    s.close()import socket

s = socket.socket()
s.connect(("example.com", 80))
s.send(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n")
banner = s.recv(1024)
print(banner.decode())
s.close()import os

ip = "192.168.1.1"
response = os.system(f"ping -c 1 {ip}")

if response == 0:
    print("Host is UP")
else:
    print("Host is DOWN")nmap 192.168.1.1
nmap -p 1-1000 192.168.1.1
nmap -sS 192.168.1.1
nmap -A example.comimport nmap

scanner = nmap.PortScanner()
scanner.scan("127.0.0.1", "1-1024")

for host in scanner.all_hosts():
    print("Host:", host)
    for proto in scanner[host].all_protocols():
        ports = scanner[host][proto].keys()
        for port in ports:
            print("Port:", port, "State:", scanner[host][proto][port]['state'])
