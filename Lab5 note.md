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



魔改了半天我还是不太懂这些端序是什么鬼

struct.pack string的方法

struct.unpack收到的其实是一个triple

* 必须用[0]获取目标

# Lab5 Report

* 计72 邹振华 2017011464



## 1 代理协议设计思路

我们对这个代理的功能预期是它工作于socks层，和socks5类似，也就是说在TCP层之上，在TLS和应用层之下，这样TCP连接我们可以用socket管理。比较麻烦的事情是socksify的过程，也就是把应用层的packet中请求的域名和端口解析出来，然后方便proxy server和用户想要访问的web service之间建立TCP连接。这个过程是依赖于应用层协议的，我们认为这部分不是我们代理协议的重点（同时也为了保证我们代理协议的通用性）。因此我们考虑的思路是，在浏览器和本地proxy client之间使用socks5协议进行通信，也就是说我们本地的proxy client同时也是一个socks5 server，我们在proxy client对浏览器发来的socks5协议包进行拆包，提取出我们需要的web service域名和端口等信息，加密后传送给proxy server，proxy server和web service之间建立TCP连接，之后我们的代理协议就可以正常加密和转发TLS和应用层的数据。

我们把我们设计的代理协议命名为***SecSocks***，我们的代理工作示意图如下：

<img src="C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212204350101.png" alt="image-20201212204350101" style="zoom: 25%;" />



## 2 SecSocks协议工作原理

### 协议泳道图

![image-20201212200452643](C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212200452643.png)

### 协议消息格式

* client发起连接，身份验证
  * key由client随机生成
  * 该消息用secsocks server的公钥加密

| CMD(1 byte) | ulen(1 byte) | plen(1 byte) | klen(1 byte)    | username(1 - 255byte) | password(1 - 255byte) | key(1 - 255byte) | padding zero(0 - 1 byte) | random str(10 byte) |
| ----------- | ------------ | ------------ | --------------- | --------------------- | --------------------- | ---------------- | ------------------------ | ------------------- |
| 0           | 用户名长度   | 密码长度     | session key长度 | 用户名                | 密码                  | session key长度  |                          | 随机串              |

* server验证身份，返回结果
  * 随机串是client之前发送的随机串
  * 该消息用secsocks server的私钥加密

| CMD(1 byte) | RESULT(1 byte) | random str(10 byte) |
| ----------- | -------------- | ------------------- |
| 1           | 0失败、1成功   | 随机串              |

* client请求连接Web服务
  * 使用session key加密

| CMD(1 byte) | atype(1 byte) | addr(4 byte) | port(2 byte) |
| ----------- | ------------- | ------------ | ------------ |
| 2           | 0(IPv4地址)   | IPv4地址     | 端口         |

| CMD(1 byte) | atype(1 byte) | alen(1 byte) | padding zero(1 byte) | addr(1 - 255 byte) | padding zero(0 - 1 byte) | port(2 byte) |
| ----------- | ------------- | ------------ | -------------------- | ------------------ | ------------------------ | ------------ |
| 2           | 1(DOMAINNAME) | 域名长度     |                      | 域名               |                          | 端口         |

* server返回连接成功或失败
  * 使用session key加密

| CMD(1 byte) | RESULT(1 byte) |
| ----------- | -------------- |
| 3           | 0(失败)        |

| CMD(1 byte) | RESULT(byte) | addr(4 byte) | port(2 byte) |
| ----------- | ------------ | ------------ | ------------ |
| 3           | 1(成功)      | 域名         | 端口         |

* 开始应用层协议数据传输
  * 使用session key加密



## 3 登录认证功能

我们实验使用的浏览器是Chrome，我们本来打算是使用Chrome的插件进行socks5的用户名和密码设置，然后在SecSocks Client拆解socks5协议包的时候直接提取出其中的用户名和密码，作为我们的SecSocks协议的登录用户名和密码。但是当我们魔改了一个Chrome的代理插件（proxy helper）以后却发现，Chrome内部的socks5 client实现根本就不支持authentication（那这个socks5形同虚设），所以我们使用了比较简陋的方式，在运行socks5 client的时候指定用户名和密码，就像下面这样

```powershell
> python .\secsocks_client.py username password
```



## 4 协议加解密

### 握手过程加密

SecSocks Client中配置有SecSocks Server的公钥，SecSocks握手请求使用公钥加密，SecSocks Server使用私钥解密；握手请求的响应使用私钥加密，使用公钥解密。

* 考虑到我们写的RSA算法比较简单，性能有限，所以我们仅每两个bytes进行加解密，所以映射空间仅仅是65536 》65536，其实比较容易破解（算法本身也只是一个雏形，这里给破解同学提供了一点思路）

* 握手过程中还传送了一个随机串，握手响应中必须携带这个随机串，以确保SecSocks Server收到了这个握手请求

* 握手请求中携带了SecSocks Client随机出来的session key，因此一步握手里同时也完成了密钥协商的工作

### 后续加密

握手过程之后的流量加密使用的都是session key，所用的算法是playfair

* 每一个TCP连接使用的都是一个单独的session key



## 5 加解密算法设计与实现



## 6 本地功能测试截图

* Chrome浏览器插件配置SecSocks代理为本地代理地址（我们的代码里附赠了一个我们稍微修改过的插件proxy helper，当然也可以其他任何可以设置sock5代理地址的Chrome插件）

![image-20201212204613076](C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212204613076.png)

<img src="C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212204635187.png" alt="image-20201212204635187" style="zoom: 33%;" />

* 运行SecSocks Server代码，监听本地9022端口

<img src="C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212204843103.png" alt="image-20201212204843103" style="zoom:50%;" />

<img src="C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212204915436.png" alt="image-20201212204915436" style="zoom: 50%;" />

* 运行SecSocks Client，指定用户名和密码，指定socks5监听本地9011端口，SecSocks试图连接9022端口

<img src="C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212205133073.png" alt="image-20201212205133073" style="zoom:50%;" />

<img src="C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212205224885.png" alt="image-20201212205224885" style="zoom:50%;" />

* 使用代理访问stack overflow

![image-20201212205450397](C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212205450397.png)

* client和server端可以查看到的代理log（左边是server，右边是client）

![image-20201212205809575](C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212205809575.png)

### 一点未解决的问题

在舍友谢兴宇的帮助下，我把这个SecSocks Server部署到了他的服务器上，但是代理效果并不理想，传输过程中很容易出现丢包的情况， 导致最终SecSocks Server传送给Web Service的数据不完整，回传的数据同样不完整，TCP连接被Web Service给reset了。目前猜想的原因可能是exchange loop中socket send和recv设置的size太大了，超出了传输路径中的闲置（把4096改更64后情况改善了很多）

<img src="C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212210604843.png" alt="image-20201212210604843" style="zoom:33%;" />

下面是size设置成64时的测试截图

![image-20201212210706260](C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212210706260.png)



## 7 实验分工

小组成员两人合作完成本次实验，邹振华同学主要负责SecSocks协议的实现，周炫柏同学主要负责加解密算法的设计与实现，两人共同完成了SecSocks协议的功能测试与验证



pip install pycryptodome

a = struct.pack("!Q", 2**64-2) 
b = struct.unpack("!Q", a)

```
import struct

count = len(barray)/2
integers = struct.unpack('H'*count, barray)
```

str to bytes

char array to bytes

bytes to char array

"".join([chr(x) for x in a])

struct.pack("!" + "B"*len(a), *[int(x) for x in a])

ord('a')

## Fresh words

circumvention 规避

