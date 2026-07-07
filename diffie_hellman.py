import random

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
        

# def generate_key(Prime:int,generator:int):

print("yes" if miller_robin_prime_test(7,100) else "NO")
    