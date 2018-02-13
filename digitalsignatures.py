from random import randint

def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)

def genkeys(n,p,g):
    sk = random_with_N_digits(n)
    #g to the power of sk mod p
    pk = pow(g,sk,p)
    return sk, pk

def sign(sk, msg, p, g):
    #difference of hash message and signature key
    d = msg - sk
    #g to the power of difference mod p
    sig = pow(g,d,p)
    return sig

def verify(pk, sig, msg, p, g):
    #g to the power of message mod p
    a = pow(g,msg, p)
    #signature message multiplied by public key mod p
    b = pow((sig*pk),1,p)
    if(a==b):
        bool = True
    else:
        bool = False
    return bool

# Unit Test
n, g, p = 56, 2, 1332417598677447461893313500475363476151903748659325311025356350620691477624842555612653603

import hashlib

m = hashlib.sha256()
m.update(b"Nobody respects")
m.update(b" the spammish repetition")
print(m.hexdigest())

skx, pkx = genkeys(n,p,g)
print("Public Key: ",pkx)

hm=int(m.hexdigest(),16)
sig= sign(skx,hm,p,g)
print("Signed message: ",sig)

print(verify(pkx,sig,hm,p,g)," should be True")
print(verify(pkx,sig,hm+1,p,g)," should be False")





