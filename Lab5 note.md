# Lab5 note

问题

* 这个socks client和socks server指的是什么，是我协议中必须实现的两个实体吗？
  * socks client指的是浏览器吗，还是说socks client是跑在本地的一个应用，浏览器把代理地址设置成这个本地的client的地址；又或者socks client实现为电脑上的一个插件？
  * 这个安全协议的加密，指的是加密socks client和socks server之间的流量吗
* 攻击者攻击的通信，是浏览器和socks client之间的通信，还是socks client和socks server之间的通信？
* 认证登录阶段，攻击者可以在浏览器和代理之间进行攻击吗？
* 浏览器配置安全协议指的是什么，是设置一个代理的地址吗？
* 加解密自己实现指的是算法也要自己实现吗
* 这种代理协议是某种常用技术吗，有没有什么参考项目可以让我们了解这个作业具体要做的是什么呢？
* 这个协议和socks5的功能是类似的吗？
* 认证过程中用了公钥算法也必须自己实现吗？

* 我们的socks proxy协议是在TCP socket之上的吧？也就是说应该可以调用socket接口？
* 不是很懂如何通过浏览器进行登录认证



什么socks？

socks工作于OSI模型的会话层（session/circuit level），全称是Socks: Protocol for sessions traversal across firewall securely，也就是“安全的回话穿墙协议”?，位于应用层和传输层之间

socks



SSL居然在第七层？

看来还要学一下SSL了

https://www.giac.org/paper/gsec/2326/understanding-implementing-socks-server-guide-set-socks-environment/104018

The proxy keeps a table of all sessions and connections

It maps the ip addresses and port numbers from inside to a single ip address and the corresponding port number

* this is NAT (network address translation)

circuit level proxy: They cannot look beyond the port number. This means they blindly trus t the destination port number of a packet. When there is something addressed to the HTTP port 80, the generic proxies treats it like a HTTP request without further checking.

socks4: Based on destination and source address respectively port number the access to the application server is granted

proxy server怎么知道destination IP的，需要先获取域名然后DNS查询吗

socks5: 客户端提议验证方法，服务器选择验证方法

* server代替client进行 name resolution是啥意思啊，是域名解析？

socksify是怎么操作的

* 怎么把original request wrap到一个socks request里面，这个是client完成的吗还是浏览器完成的？

socks server evaluates the original request这个是怎么操作的，需要分不同的应用层协议来evaluate吗

这个reference 13是啥，感觉讲得蛮详细

CONNECT请求？BIND操作？

浏览器会直接完成socksify的操作吗？



研究一下参考代码是怎么进行socket会话管理的

* client发起连接，身份验证(用配置的server公钥加密)
  * key由client随机生成

| CMD(1 byte) | ulen(1 byte) | username(1 - 255 byte) | plen(1 byte) | password(1 - 255byte) | klen(1 byte) | key(1 - 255byte) |
| ----------- | ------------ | ---------------------- | ------------ | --------------------- | ------------ | ---------------- |
| 0           |              |                        |              |                       |              |                  |

* server验证身份，返回结果

| CMD(1 byte) | RESULT(1 byte) |
| ----------- | -------------- |
| 1           | 0失败、1成功   |

* client请求连接Web服务

| CMD(1 byte) | atype(1 byte)              | alen(1 byte) | addr(1 - 255 byte) | port(2 byte) |
| ----------- | -------------------------- | ------------ | ------------------ | ------------ |
| 2           | 0(IPV4地址)，1(DOMAINNAME) |              |                    |              |

* server返回连接成功或失败

| CMD(1 byte) | RESULT(1 byte) |
| ----------- | -------------- |
| 3           | 0(失败)        |

| CMD(1 byte) | RESULT(byte) | addr(4 byte) | port(2 byte) |
| ----------- | ------------ | ------------ | ------------ |
| 3           | 1(成功)      |              |              |

* 开始传输



魔改了半天我还是不太懂这些端序是什么鬼

struct.pack string的方法

struct.unpack收到的其实是一个triple

* 必须用[0]获取目标





## Fresh words

circumvention 规避

