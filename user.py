import socket
queries = ['google.com']
forward_addr = ("127.0.0.1", 5005)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in queries:
    print(f"Starting query for: {i}")
    client.sendto(i.encode(), forward_addr)
    data, _ = client.recvfrom(1024)
    print(f"Received: {data.decode()}\n\n")