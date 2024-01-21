import socket
import ssl
from scapy.all import *

def initiate_connection(destination, port):
    print(f"destination {destination} port {port}")
    try:
        # Initiate a TCP connection
        client_socket = socket.create_connection((destination, port))

        # added by me because I think it's needed, but not sure.
        # context = ssl.create_default_context()

        # Wrap the socket with SSL/TLS
        tls_socket = ssl.wrap_socket(client_socket, ssl_version=ssl.PROTOCOL_TLS)
        # tls_socket = context.wrap_socket(client_socket, destination)

        # Send a simple request
        tls_socket.send(b"GET / HTTP/1.0\r\n\r\n")

        # Receive the response
        response = tls_socket.recv(4096)

        # Close the connection
        tls_socket.close()

        print(f"*** connect response completed {response}")
        print()

        return response

    except Exception as e:
        print(f"Error during connection: {e}")
        return None

def is_tls_packet(packet):
    print("*** is_tls called")
    return packet.haslayer(TCP) and packet.haslayer(Raw) and b'\x16\x03\x01' in packet[Raw].load

def test_response_packets(destination, port):
    response = initiate_connection(destination, port)

    if response:
        # Use Scapy to analyze response packets
        response_packets = Ether(response)
        print(response_packets)

        # print(response_packets)
        for packet in response_packets:
            # print(packet.show())
            if is_tls_packet(packet):
                print("TLS packet found:")
                #print(packet.summary())

def main():
    destination = "google.com"  # Replace with your target
    port = 443

    test_response_packets(destination, port)

if __name__ == "__main__":
    main()
