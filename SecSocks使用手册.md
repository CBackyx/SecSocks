# SecSocks 使用手册

* 下面我们假设源码根目录是 ~/

* 由于我们的client和server是多线程的，所以可能出现Ctrl + C无法退出的情况，目前没有找到比较好的解决办法，所以这种情况只能关闭Terminal了，实在抱歉QAQ



## 1 RSA秘钥生成与设置

在 ~/rsa/ 目录下运行rsa.py文件你将会得到三个素数，分别是n，e，d，如下：

```
13851239800495236719
49627
9882339197457334123
```

n和e组合成公钥，复制到 ~/client/rsa_server.py中，如下：

```python
n = 13851239800495236719
e = 49627

def rsa_encrypt(a):
    b = []
    for i in range(len(a)):
        b.append(pow(a[i],e,n))
    # print(b)
    return b
```

n和d组合成私钥，复制到 ~/sever/rsa_server.py中，如下：

```python
n = 13851239800495236719
d = 9882339197457334123

def rsa_decrypt(a):
    b = []
    for i in range(len(a)):
        b.append(pow(a[i],d,n))
    # print(b)
    return b
```



## 2  SecSocks Client配置

* **配置socks5监听地址端口，配置SecSocks Server地址端口**

在~/client/secsocks_client.py中配置，如下：

<img src="C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212212815378.png" alt="image-20201212212815378" style="zoom: 50%;" />



## 3 SecSocks Server配置监听地址和端口

在~/server/secsocks_server.py中配置，如下：

<img src="C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212212959249.png" alt="image-20201212212959249" style="zoom:50%;" />



## 4 Chrome浏览器代理设置

我们在~/extension/目录下放了一个我们稍微修改过的proxy helper插件，你可以在Chrome浏览器的 "管理扩展程序" 》 "加载已解压的扩展程序" 中添加这个插件

* 你也可以选择其他插件，只要它可以指定socks5代理地址和端口

"右键插件图标" 》"选项" 可以进入配置页面，配置SecSocks Client的地址和端口，示例如下

<img src="C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212213518596.png" alt="image-20201212213518596" style="zoom: 33%;" />

配置后请开启SecSocks代理

<img src="C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212213328984.png" alt="image-20201212213328984" style="zoom:50%;" />



## 5 运行server脚本

在 ~/server/ 目录下运行

```
python .\secsocks_server.py
```



## 6 运行client脚本（指定用户名和密码）

```
python .\secsocks_client.py username password
```

* 注意：用户名和密码我们目前硬编码在了 ~/server/secsocks_server.py 文件的这个位置，你可以设置

<img src="C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212213858546.png" alt="image-20201212213858546" style="zoom:50%;" />



## 7 开始冲浪

![image-20201212214304474](C:\Users\CBackyxM\AppData\Roaming\Typora\typora-user-images\image-20201212214304474.png)

### 使用curl的测试

```
curl --socks5-hostname 127.0.0.1:9011 https://www.baidu.com
```

