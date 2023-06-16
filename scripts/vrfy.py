import socket
import sys
if len(sys.argv) != 2:
    print("Usage: vrfy.py <username>")
    sys.exit(0)
# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect to the Server
connect = s.connect(('10.129.149.247',25))
# Receive the banner
banner = s.recv(1024)
print(banner)
with open(sys.argv[1], 'r') as f:
    for line in f:
        line = line.strip()
        # VRFY a user
        s.send(('VRFY ' + line + '\r\n').encode())
        result = s.recv(1024).decode()
        if not result.startswith('550'):
            print(result, end='')
# Close the socket
s.close()