import logging
import select
import socket
import struct
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

logging.basicConfig(level=logging.DEBUG)
SOCKS_VERSION = 5

SEC_AUTH_REQ_CMD = 0
SEC_AUTH_RES_CMD = 1
SEC_CON_REQ_CMD = 2
SEC_CON_RES_CMD = 3

sec_server_address = '127.0.0.1'
sec_server_port = 9022

socks5_server_address = '127.0.0.1'
socks5_server_port = 9011


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):

    def handle(self):
        logging.info('Accepting connection from %s:%s' % self.client_address)

        # greeting header
        # read and unpack 2 bytes from a client
        header = self.connection.recv(2)
        version, nmethods = struct.unpack("!BB", header)

        # socks 5
        # print(version, " version")
        assert version == SOCKS_VERSION
        assert nmethods > 0

        # get available methods
        methods = self.get_available_methods(nmethods)

        # accept only USERNAME/PASSWORD auth
        # 0 是无验证
        # 2 是用户名和密码验证
        # print("set(methods) ", set(methods))
        if 2 not in set(methods):
            # close connection
            print("close")
            self.server.close_request(self.request)
            return

        # 和sec remote连接
        try:
            sec_remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sec_remote.connect((sec_server_address, sec_server_port))
        
        except Exception as err:
            logging.error(err)
            self.server.close_request(self.request)
            return

        # send welcome message
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))            

        # user验证
        if not self.verify_credentials(sec_remote):
            return

        # request
        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION

        if address_type == 1:  # IPv4
            address = struct.unpack("!I", self.connection.recv(4))[0]
            port = struct.unpack('!H', self.connection.recv(2))[0]
            sec_request = struct.pack("!BBIH", SEC_CON_REQ_CMD, 0, address, port)
        elif address_type == 3:  # Domain name
            domain_length = self.connection.recv(1)[0]
            address = self.connection.recv(domain_length).decode('utf-8')
            port = struct.unpack('!H', self.connection.recv(2))[0]
            sec_request = struct.pack("!BBB%dsH" % (domain_length,), SEC_CON_REQ_CMD, 1, domain_length, address, port)
        
        # 请求sec remote和web建立连接
        sec_remote.send(sec_request)

        sec_cmd = ord(sec_remote.recv(1))
        if sec_cmd != SEC_CON_RES_CMD:
            self.server.close_request(self.request)
            return

        sec_result = ord(sec_remote.recv(1))
        if sec_result != 1:
            self.server.close_request(self.request)
            return

        web_addr, web_port = struct.unpack("!IH", sec_remote.recv(6))

        # reply
        reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, 1,
                            web_addr, web_port)

        self.connection.sendall(reply)

        # establish data exchange
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(self.connection, sec_remote)

        self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_credentials(self, sec_remote):
        version = ord(self.connection.recv(1))
        assert version == 1

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len)

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len)
        
        # 向sec remote做验证 
        # print("h1")
        sec_request = struct.pack("!BB%dsB%ds" % (username_len, password_len, ), SEC_AUTH_REQ_CMD, username_len, username, password_len, password)
        sec_remote.sendall(sec_request)
        # print("h2")
        sec_cmd, sec_result = struct.unpack("!BB", sec_remote.recv(2))

        if sec_cmd != SEC_AUTH_RES_CMD:
            self.server.close_request(self.request)
            return False

        if sec_result == 1:
            # success, status = 0
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            return True

        # failure, status != 0
        response = struct.pack("!BB", version, 0xFF)
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
    with ThreadingTCPServer((socks5_server_address, socks5_server_port), SocksProxy) as server:
        server.serve_forever()
