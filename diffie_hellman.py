import random
import secrets


def random_n_bits_odd(n):
    x = secrets.randbits(n)
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
            x = pow(a, d, number)
            
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

# print("yes" if miller_robin_prime_test(7,100) else "NO")
print(generate_n_bit_prime(128))
    