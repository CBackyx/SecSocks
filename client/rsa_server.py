n = 13851239800495236719
e = 49627

def rsa_encrypt(a):
    b = []
    for i in range(len(a)):
        b.append(pow(a[i],e,n))
    # print(b)
    return b