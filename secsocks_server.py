import logging
import select
import socket
import struct
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

logging.basicConfig(level=logging.DEBUG)

SEC_AUTH_REQ_CMD = 0
SEC_AUTH_RES_CMD = 1
SEC_CON_REQ_CMD = 2
SEC_CON_RES_CMD = 3

sec_server_address = '127.0.0.1'
sec_server_port = 9022


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SecSocksProxy(StreamRequestHandler):
    username = 'username'
    password = 'password'

    def handle(self):
        logging.info('Accepting connection from %s:%s' % self.client_address)

        # user验证
        if not self.verify_credentials():
            return

        # request
        sec_cmd, address_type = struct.unpack("!BB", self.connection.recv(2))

        if sec_cmd != SEC_CON_REQ_CMD:
            self.server.close_request(self.request)
            return False

        if address_type == 0:  # IPv4
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 1:  # Domain name
            domain_length = self.connection.recv(1)[0]
            address = self.connection.recv(domain_length)
            address = socket.gethostbyname(address)
        port = struct.unpack('!H', self.connection.recv(2))[0]

        # reply
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((address, port))
            bind_address = remote.getsockname()
            logging.info('Connected to %s %s' % (address, port))

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBIH", SEC_CON_RES_CMD, 1, addr, port)

        except Exception as err:
            logging.error(err)
            # return connection refused error
            reply = struct.pack("!BB", SEC_CON_RES_CMD, 0)

        self.connection.sendall(reply)

        # establish data exchange
        if reply[1] == 1:
            self.exchange_loop(self.connection, remote)

        self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_credentials(self):

        sec_cmd = ord(self.connection.recv(1))
        if sec_cmd != SEC_AUTH_REQ_CMD:
            self.server.close_request(self.request)
            return False

        # print("h1")
        username_len = ord(self.connection.recv(1))
        # print(username_len)
        username = self.connection.recv(username_len).decode('utf-8')
        # print(username)
        # print("h2")
        password_len = ord(self.connection.recv(1))
        # print(password_len)
        password = self.connection.recv(password_len).decode('utf-8')

        # print(username, " ", password)
        if username == self.username and password == self.password:
            # success, status = 0
            response = struct.pack("!BB", SEC_AUTH_RES_CMD, 1)
            self.connection.sendall(response)
            return True

        # failure, status != 0
        response = struct.pack("!BB", SEC_AUTH_RES_CMD, 0)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def exchange_loop(self, client, remote):

        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break


if __name__ == '__main__':
    with ThreadingTCPServer((sec_server_address, sec_server_port), SecSocksProxy) as server:
        server.serve_forever()
