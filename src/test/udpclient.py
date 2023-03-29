# UDP Echo Client

import socket

send = b"Hello World!"
address = ("127.0.0.1", 20001)
buffer = 1024

def udpclient():
  udp = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
  udp.sendto(send, address)
  received = udp.recvfrom(buffer)
  msg = f"Message Received: {received[0]}"
  print(msg)
 
if __name__ == "__main__":
  udpclient()
