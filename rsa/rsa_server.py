# filename = 'rsa_test.txt'
# with open(filename, 'r') as f:
#     n = int(f.readline()[:-1])
#     e = int(f.readline()[:-1])
#     d = int(f.readline())

# print(n)
# print(e)
# print(d)

n = 13851239800495236719
e = 49627
d = 9882339197457334123

def rsa_encrypt(a):
    b = []
    for i in range(len(a)):
        b.append(pow(a[i],e,n))
    # print(b)
    return b

def rsa_decrypt(a):
    b = []
    for i in range(len(a)):
        b.append(pow(a[i],d,n))
    # print(b)
    return b

# print(bytes)
# mm = encrypt(bytes)
# result = decrypt(mm)
# print(bytearray(result))