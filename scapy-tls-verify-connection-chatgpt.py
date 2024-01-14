import socket
import ssl
from scapy.all import *

def initiate_connection(destination, port):
    try:
        # Initiate a TCP connection
        client_socket = socket.create_connection((destination, port))

        # Wrap the socket with SSL/TLS
        tls_socket = ssl.wrap_socket(client_socket, ssl_version=ssl.PROTOCOL_SSLv23)

        # Send a simple request
        tls_socket.send(b"GET / HTTP/1.0\r\n\r\n")

        # Receive the response
        response = tls_socket.recv(1024)

        # Close the connection
        tls_socket.close()

        return response

    except Exception as e:
        print(f"Error during connection: {e}")
        return None

def is_tls_response(response):
    # Check if the response contains TLS indicators (adjust as needed)
    return b'\x16\x03\x01' in response

def main():
    destination = "example.com"  # Replace with your target
    port = 443

    response = initiate_connection(destination, port)

    if response and is_tls_response(response):
        print("TLS response received.")
    else:
        print("No TLS response.")

if __name__ == "__main__":
    main()
