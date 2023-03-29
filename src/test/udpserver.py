# UDP Echo Server

import socket

ip = "127.0.0.1"
port = 20001
buffer = 1024

def udpserver():
    udp = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    udp.bind((ip, port))
    print("Created UDP Server")
    while True:
        pair = udp.recvfrom(buffer)
        pr = f"Message Received:{pair[0]}, Client IP:{pair[1]}"
        print(pr)
        udp.sendto(pair[0], pair[1])

if __name__ == "__main__":
    udpserver()
