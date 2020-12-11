import logging
import select
import socket
import struct
import sys
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from rsa_server import *
from playfair import *
from random import *

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

username = ""
username_len = 0
password = ""
password_len = 0


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksProxy(StreamRequestHandler):

    def handle(self):

        self.s_key = ""
        self.s_key_len = 0
        self.s_arr = ""

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
        if 0 not in set(methods):
            # close connection
            print("close")
            self.server.close_request(self.request)
            return

        # 计算session key
        self.s_key_len, self.s_key = skey()
        self.s_arr = get_s_arr(self.s_key)

        # 和sec remote连接
        try:
            sec_remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sec_remote.connect((sec_server_address, sec_server_port))
        
        except Exception as err:
            logging.error(err)
            self.server.close_request(self.request)
            return

        print("listening port: ", sock.getsockname()[1])

        # send welcome message
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0))            

        # user验证, RSA加解密---------------------------------
        if not self.verify_credentials(sec_remote):
            return

        # 获取web地址
        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION

        if address_type == 1:  # IPv4
            address = struct.unpack("!I", self.connection.recv(4))[0]
            port = struct.unpack('!H', self.connection.recv(2))[0]
            sec_request = struct.pack("!BBIH", SEC_CON_REQ_CMD, 0, address, port)
        elif address_type == 3:  # Domain name
            domain_length = self.connection.recv(1)[0]
            address = self.connection.recv(domain_length)
            port = struct.unpack('!H', self.connection.recv(2))[0]
            if domain_length % 2 == 0:
                sec_request = struct.pack("!BBBB%dsH" % (domain_length,), SEC_CON_REQ_CMD, 1, domain_length, 0, address, port)
            else:
                sec_request = struct.pack("!BBBB%dsBH" % (domain_length,), SEC_CON_REQ_CMD, 1, domain_length, 0, address, 0, port)
        
        # playfair加解密 -------------------------------------
        # 请求sec remote和web建立连接
        sec_remote.send(self.do_pf_encrypt(sec_request))

        sec_cmd, sec_result = struct.unpack("!BB", self.do_pf_decrypt(sec_remote.recv(2)))
        if sec_cmd != SEC_CON_RES_CMD:
            self.server.close_request(self.request)
            return

        if sec_result != 1:
            self.server.close_request(self.request)
            return

        # web连接成功
        web_addr, web_port = struct.unpack("!IH", self.do_pf_decrypt(sec_remote.recv(6)))

        # 回复浏览器
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
        
        # 向sec remote做验证 
        # print("h1")
        global username
        global username_len
        global password
        global password_len

        # encode并加密握手请求
        rand_str = bytearray([choice(range(255)) for i in range(10)])

        encoded_key = struct.pack("!" + "B"*len(self.s_key), *[ord(x) for x in self.s_key])
        if (username_len + password_len + self.s_key_len) % 2 == 0:
            sec_request = struct.pack("!BBBB%ds%ds%ds10s" % (username_len, password_len, self.s_key_len), SEC_AUTH_REQ_CMD, username_len, password_len, self.s_key_len, \
                            username.encode(), password.encode(), encoded_key, rand_str)
        else: # need padding
            sec_request = struct.pack("!BBBB%ds%ds%dsB10s" % (username_len, password_len, self.s_key_len), SEC_AUTH_REQ_CMD, username_len, password_len, self.s_key_len, \
                            username.encode(), password.encode(), encoded_key, 0, rand_str)
        sec_remote.sendall(self.do_rsa_encrypt(sec_request))
        
        # 接受server回复握手
        sec_cmd, sec_result, res_rand_str = struct.unpack("!BB10s", self.do_rsa_decrypt(sec_remote.recv(48)))

        # 握手失败，服务器响应错误
        if sec_cmd != SEC_AUTH_RES_CMD or rand_str != res_rand_str:
            self.server.close_request(self.request)
            sec_remote.close()
            print("Connection error: server handshake error!")
            return False

        # 握手成功
        if sec_result == 1:
            # success, status = 0
            print("Login success!")
            return True

        # 握手失败，用户名或密码错误
        print("Login failed! Check your username and password!")
        self.server.close_request(self.request)
        sec_remote.close()
        return False


    def do_pf_encrypt(self, data):
        print(data)
        print("s_key ", self.s_key[:20])
        print("test ", pf_crypt(b'\x02\x01', self.s_arr))
        data = pf_crypt(data, self.s_arr)
        print(data)
        return data
        

    def do_pf_decrypt(self, data):
        print(data)
        data = pf_crypt(data, self.s_arr)
        print(data)
        return data
        


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Error arg nums!")
        exit(-1)
    username = sys.argv[1]
    username_len = len(username)
    password = sys.argv[2]
    password_len = len(password)
    with ThreadingTCPServer((socks5_server_address, socks5_server_port), SocksProxy) as server:
        server.serve_forever()
