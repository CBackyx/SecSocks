import logging
import select
import socket
import struct
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from rsa_server import *
from playfair import *
from random import *

logging.basicConfig(level=logging.DEBUG)

SEC_AUTH_REQ_CMD = 0
SEC_AUTH_RES_CMD = 1
SEC_CON_REQ_CMD = 2
SEC_CON_RES_CMD = 3

sec_server_address = '0.0.0.0'
sec_server_port = 9022


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SecSocksProxy(StreamRequestHandler):
    username = 'username'
    password = 'password'

    def handle(self):

        self.s_key = ""
        self.s_key_len = 0
        self.s_arr = ""

        logging.info('Accepting connection from %s:%s' % self.client_address)

        self.listenport = self.connection.getpeername()[1]

        # user登录验证，协商session key
        if not self.verify_credentials():
            return

        # 接收web连接请求
        sec_cmd, address_type = struct.unpack("!BB", self.do_pf_decrypt(self.connection.recv(2)))

        if sec_cmd != SEC_CON_REQ_CMD:
            print(sec_cmd)
            print("is not SEC_CON")
            self.server.close_request(self.request)
            return False

        print("addr resolving")
        # 地址解析
        if address_type == 0:  # IPv4
            address = socket.inet_ntoa(self.do_pf_decrypt(self.connection.recv(4)))
        elif address_type == 1:  # Domain name
            domain_length, _ = struct.unpack("!BB", self.do_pf_decrypt(self.connection.recv(2)))
            if domain_length % 2  == 0:
                address = self.do_pf_decrypt(self.connection.recv(domain_length))
            else:
                address = (self.do_pf_decrypt(self.connection.recv(domain_length + 1)))[:domain_length]
            address = socket.gethostbyname(address)
        port = struct.unpack('!H', self.do_pf_decrypt(self.connection.recv(2)))[0]

        # 尝试连接web服务
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect((address, port))
            bind_address = remote.getsockname()
            logging.info('Connected to %s %s' % (address, port))

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBIH", SEC_CON_RES_CMD, 1, addr, port)
            # 连接成功
            print("connect success!")
            _suc = True

        except Exception as err:
            logging.error(err)
            reply = struct.pack("!BB", SEC_CON_RES_CMD, 0)
            # 连接失败
            print("connect failed!")
            _suc = False

        reply = self.do_pf_encrypt(reply)
        self.connection.sendall(reply)

        # establish data exchange
        if _suc:
            print("连接成功")
            self.exchange_loop(self.connection, remote)

        self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_credentials(self):

        # 获取握手请求中的CMD，用户名长度，密码长度，session key长度
        sec_cmd, username_len, password_len, self.s_key_len = struct.unpack("!BBBB", self.do_rsa_decrypt(self.connection.recv(16)))
        if sec_cmd != SEC_AUTH_REQ_CMD:
            self.server.close_request(self.request)
            return False

        # 接受用户名、密码、session key
        if (username_len + password_len + self.s_key_len) % 2 == 0:
            username, password, self.s_key = struct.unpack("!%ds%ds%ds" % (username_len, password_len, self.s_key_len,), \
                self.do_rsa_decrypt(self.connection.recv((username_len + password_len + self.s_key_len) * 4)))
        else:
            username, password, self.s_key, _ = struct.unpack("!%ds%ds%dsB" % (username_len, password_len, self.s_key_len,), \
                self.do_rsa_decrypt(self.connection.recv((username_len + password_len + self.s_key_len + 1) * 4)))
        
        # 生成s_arr
        self.s_key = "".join([chr(x) for x in self.s_key])
        # print("s_key ", self.s_key[:20])
        self.s_arr = get_s_arr(self.s_key)

        username = username.decode('utf-8')
        password = password.decode('utf-8')

        # 解析rand_str
        rand_str = struct.unpack("!10s", self.do_rsa_decrypt(self.connection.recv(40)))[0]

        # 验证用户名和密码
        if username == self.username and password == self.password:
            # 登录成功
            response = self.do_rsa_encrypt(struct.pack("!BB10s", SEC_AUTH_RES_CMD, 1, rand_str))
            self.connection.sendall(response)
            print("login success!")
            return True

        # 用户名或密码错误，登录失败
        response = self.do_rsa_encrypt(struct.pack("!BB10s", SEC_AUTH_RES_CMD, 0, rand_str))
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def exchange_loop(self, client, remote):

        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                # print("data", len(data))
                data = self.do_pf_decrypt(data)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                # print("data", len(data))
                data = self.do_pf_encrypt(data)
                if client.send(data) <= 0:
                    break

    # input and output are bytes
    def do_rsa_encrypt(self, sec_request):
        text_len = int(len(sec_request) / 2)
        if text_len == 0:
            return
        # print(len(sec_request))
        # print(text_len)
        sec_request = struct.unpack("!" + "H"*text_len, sec_request)
        sec_request = rsa_decrypt(sec_request)
        sec_request = struct.pack("!" + "Q"*text_len, *sec_request)
        return sec_request

    # input and output are bytes
    def do_rsa_decrypt(self, sec_response):
        text_len = int(len(sec_response) / 8)
        if text_len == 0:
            return
        # print(text_len)
        # print(len(sec_response))
        sec_response = struct.unpack("!" + "Q"*text_len, sec_response)
        sec_response = rsa_decrypt(sec_response)
        sec_response = struct.pack("!" + "H"*text_len, *sec_response)
        return sec_response

    def do_pf_encrypt(self, data):
        # print(data)
        data = pf_crypt(data, self.s_arr)
        # print(data)
        return data

    def do_pf_decrypt(self, data):
        # print(data)
        # print("listening port: ", self.listenport, "s_key ", self.s_key, "len_key ", len(self.s_key), self.s_arr[:20], get_s_arr(self.s_key)[:20], "test ", pf_crypt(b'\x02\x01', self.s_arr))
        data = pf_crypt(data, self.s_arr)
        # print(data)
        return data

if __name__ == '__main__':
    with ThreadingTCPServer((sec_server_address, sec_server_port), SecSocksProxy) as server:
        server.serve_forever()
