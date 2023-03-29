import socket

localIP = "127.0.0.1"
localPort = 20001
bufferSize = 1024

bytesToSend = f"Hello UDP Client"
udp = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
udp.bind((localIP, localPort))

print("UDP server up and listening")

def udpserver():
    while(True):
        pair = udp.recvfrom(bufferSize)
        message = pair[0]
        address = pair[1]

        msg = "Message from Client:{}".format(message)
        addr = "Client IP Address:{}".format(address)

        print(msg)
        print(addr)

        udp.sendto(bytesToSend, address)

if __name__ == "__main__":
    udpserver()
