import random
import math
# import secrets


def random_n_bits_odd(n:int):
    x = random.getrandbits(n)
    x|=(1<<(n-1))
    x|=1
    return x    
    
def miller_robin_prime_test(number:int,rounds:int):
    if(number==2 or number==3):
        return True
    
    if(number<=1 or number%2==0):
        return False
        
    d=number-1
    s=0
    while d%2==0:
        d//=2
        s+=1
    
    for _ in range(rounds):
        a= random.randint(2, number-2)
        
        x = pow(a, d, number)
        if x==1 or x==number-1:
            continue
        for _ in range(s-1):
            x = pow(x, 2, number)
            
            if x== number-1:
                break
            
        if x!=number-1:
            return False
        
    return True
        

def generate_n_bit_prime(n:int):
    while True:
        p=random_n_bits_odd(n)
        
        if miller_robin_prime_test(p,100):
            return p
            break
def generate_safe_primes(bits):
    while True:
        q = generate_n_bit_prime(bits - 1)
        P = 2 * q + 1

        if miller_robin_prime_test(P, 100):
            return P, q
    
# prime factorization is too slow
def prime_factors(n:int):
    factors=set()
    while n%2==0:
        factors.add(2)
        n//=2
    i=3
    limit = math.isqrt(n)
    for i in range(3,n + 1, 2):
        while n%i==0:
            factors.add(i)
            n//=i
    
    if n>1:
        factors.add(n)
        
    return list(factors)
    
def find_generator(Prime:int,q:int):
    factors=[q,2]
    
    while True:
        generator=random.randint(2, Prime-2)
        
        if not (pow(generator,(Prime-1)//2,Prime)==1 or pow(generator,(Prime-1)//q,Prime)==1):
            break
        
    return generator

def generate_keys(generator: int, prime: int):
    private = random.randrange(2, prime - 1)
    public = pow(generator, private, prime)
    return private, public

def compute_shared_secret(their_public: int, my_private: int, prime: int) -> int:
    return pow(their_public, my_private, prime)

def verify_shared_secret(A:int,B:int,a:int,b:int,P:int):
    if pow(B,a,P)!=pow(A,b,P):
        return False
    return True