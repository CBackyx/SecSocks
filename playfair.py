from random import *
import struct

#生成一个n位的随机数
def ran_num():
    n = choice([110,120,130,140,150])
    str = "".join([choice("0123456789ABCDEF") for i in range(n)])
    return str

#用生成的随机数来组成session key —— 同样只能用一次，保证对称密钥不会改变
def skey():
    a = ""
    str = ran_num()
    for i in range(len(str) // 2):
        chr1 = int(str[i],16)
        chr2 = int(str[i+1],16)
        i = i + 2
        str += chr(16*chr1+chr2)
    return len(''.join(set(str))), ''.join(set(str))

#构筑新的16*16映射表
def get_s_arr(s_key):
    b = list()
    s = set()
    for i in range(len(s_key)):
        if not (s_key[i] in s): 
            b.append(s_key[i])
            s.add(s_key[i])
    
    for i in range(256):
        if not chr(i) in s:
            b.append(chr(i))
            s.add(chr(i))
    return b

#加解密
def pf_crypt(a,s_arr):
    a = "".join([chr(x) for x in a])
    b = []
    i = 0
    while i in range(len(a)):
        #如果最后只剩下一个字母，则不变换，直接放入加密串中
        if i+1 >= len(a):
            b.append(a[i])
            break
        #如果一对字母中的两个字母相同，则不变换，直接放入加密串中
        if a[i] == a[i+1]:
            b.append(a[i])
            b.append(a[i+1])
            i += 2
            continue
        #如果字母对出现在方阵中的同一行或同一列，则只需简单对调这两个字母
        # print("a[i] ", int(a[i]))
        ind1 = s_arr.index(a[i])
        ind2 = s_arr.index(a[i+1])
        if (ind1 // 16 == ind2 // 16) or (ind1 % 16 == ind2 % 16):
            b.append(a[i+1])
            b.append(a[i])
        #如果有以字母对为顶点的矩形,则该矩形的另一对顶点字母中，与a同行的字母应在前面
        else:
            b.append(s_arr[(ind1 // 16)*16 + (ind2 % 16)])
            b.append(s_arr[(ind2 // 16)*16 + (ind1 % 16)])
        i += 2
    b = "".join(b)
    b = struct.pack("!" + "B"*len(b), *[ord(x) for x in b])
    return b

# k_len, s_key = skey()
# s_arr = get_s_arr(s_key)
# # # import struct
# # print([x.encode() for x in s_arr])
# # print(a)
# # a = b'\xfa\x1e'
# a = b'\x02\x01'
# a = b'\x02\x01\x14\x00beacons.gcp.gvt2.com\x01\xbb'
# # # print(s_arr)
# b = pf_crypt(a,s_arr)
# c = pf_crypt(b,s_arr)
# # print("".join(c).encode())
# print(b)
# print(c)