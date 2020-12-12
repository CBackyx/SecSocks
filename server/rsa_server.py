n = 13851239800495236719
d = 9882339197457334123

def rsa_decrypt(a):
    b = []
    for i in range(len(a)):
        b.append(pow(a[i],d,n))
    # print(b)
    return b