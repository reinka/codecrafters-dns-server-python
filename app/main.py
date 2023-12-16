import socket


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 2053))
        while True:
            try:
                data, addr = s.recvfrom(1024)
                print(f'Received data from {addr}')
                s.sendto(data, addr)
            except Exception as e:
                print(f'Error receiving data {e}')
                break

if __name__ == "__main__":
    main()
