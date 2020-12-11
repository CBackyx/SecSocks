from Crypto.Util.number import *

def gcd(a,b):
    if a%b == 0:
        return b
    else :
        return gcd(b,a%b)

def isPrime(a,b):
    if gcd(a,b) == 1:
        return True
    else :
        return False

# 求私钥
def rsa_get_key(e, euler):
    k = 1
    while True:
        if (((euler * k) + 1) % e) == 0:
            return (euler * k + 1) // e
        k += 1

# 根据n,e计算d
def getd(e):
    euler = (p-1)*(q-1)
    k = 1
    while True:
        if (((euler * k) + 1) % e) == 0:
            return (euler * k + 1) // e
        k += 1

p = getPrime(32) 
q = getPrime(32) 
n = p*q

e = 0
while True:
    e = getPrime(16)
    if isPrime(n,e) == True :
        break

d = getd(e)

filename = 'rsa_test.txt'
with open(filename, 'a') as file_object:
    file_object.seek(0)
    file_object.truncate()
    file_object.write(str(n))
    file_object.write('\n')
    file_object.write(str(e))
    file_object.write('\n')
    file_object.write(str(d))