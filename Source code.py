'''

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~  RSA - 2048  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

RSA - Encryption and Decryption using BitVector class.
Project 209
Authors - Swara, Kishan, Divya
'''

from BitVector import *
from random import randint


'''
primes()    --  This function will create prime Number.
            --  It will be 308 bit in Decimal Number System.
'''
def primes():
    def fermat(n):                  # THIS WILL CHECK WHETHER THE NUMBER IS PRIME OR NOT
        if n == 2:
            return True
        if not n & 1:
            return False
        return pow(2, n-1, n) == 1

    a = 10 ** 307                   # FIRST 308 DIGIT LONG DECIMAL NUMBER
    b = (10 ** 308)-1               # LAST 308 DIGIT LONG DECIMAL NUMBER

    for i in range(0,1000000):

        rand = randint(a, b)           # THIS WILL CREATE THE RANDOM NUMBER BETWEEN FIRST AND LAST NUMBER

        if fermat(rand):
            break

    return rand


'''
gcd(,)

Euclid's algorithm for determining the greatest common divisor
Using iteration to make it faster for larger integers
'''

def gcd(a, b):

    while b != 0:
        a, b = b, a % b
    return a

'''
is_prime()

THIS FUNCTION WILL RAISE AN ERROR IF OUR PROGRAM MISTAKENLY PICK A NON-PRIME NUMBER :P
(THIS CAN'T HAPPEN BECAUSE THERE IS A FUNCTION FOR THE PRIME NUMBER BUT WE KEEP IT JUST FOR MORE SECURITY)
'''

def is_prime(n):
    if n == 2:
        return True
    if not n & 1:
        return False
    return pow(2, n-1, n) == 1

'''
THIS FUNCTION WILL CREATE THE 'PUBLIC KEY' FOR THE ENCRYPTION PROCESS
selecting_e()       --  TWO CONDITIONS NEED TO BE SATISFIED FOR THE SELECTION OF PUBLIC KEY 'E'
                    --  1 < E < PHI
                    --  'E' MUST BE CO-PRIME WITH 'PHI'
'''
def selecting_e(phi):

    for e in range(3,phi,2):
        co_prime_phi = gcd(e,phi)

        if co_prime_phi == 1:
            break

    return e                        # THIS WILL RETURN THE PUBLIC KEY 'E' FOR ENCRYPTION


'''
THIS FUNCTION WILL CREATE THE PUBLIC AND PRIVATE KEY FOR THE ENCRYPTION AND DECRYPTION RESPECTIVEL
generate_keypair(,)        --  IN THIS FUNCTION, THERE IS ONE OTHER FUNCTION FOR CREATING PUBLIC KEY
                          --  selecting_e() FOR PUBLIC KEY

'''

def generate_keypair(p_bv, q_bv):

    p = p_bv.intValue()
    q = q_bv.intValue()

    if not (is_prime(p) and is_prime(q)):               # THIS WILL RECHECK THAT WHETHER THE NUMBERS ARE PRIME OR NOT
        raise ValueError('Both numbers must be prime.') # ERROR MESSAGE
    elif p == q:
        raise ValueError('p and q cannot be equal')     # ERROR MESSAGE

    n = p * q

    n_bv = BitVector(intVal = n)

    p1 = p_bv.intValue()
    q1 = q_bv.intValue()

    p1 = p1-1
    q1 = q1-1

    phi = p1 * q1
    phi_bv = BitVector(size=0)
    phi_bv = BitVector(intVal = phi)

    # Choose an integer e such that e is co-prime with phi
    e = selecting_e(phi)
    print('Value of E:',e)
    print('')
    e_bv = BitVector(size=0)
    e_bv = BitVector(intVal = e)
    print('BitVector representation of Public Key E: ',e_bv)
    print('')

    '''
        NOW, WE ARE CREATING THE PRIVATE KEY 'D' FOR THE DECRYPTION PROCESS.
        PRIVATE KEY IS CREATED USING 'MULTIPLICATIVE_INVERSE()' FUNCTION
        THIS FUNCTION IS PRE-DEFINED IN BITVECTOR CLASS
        THIS WILL SELECT THE INVERSE NUMBER OF THE PUBLIC KEY 'E' WHICH IS OUR PRIVATE KEY 'D'
    '''

    bv_modulus = BitVector(intVal = phi)
    bv = BitVector(intVal = e)
    bv_result = bv.multiplicative_inverse(bv_modulus)
    if bv_result is not None:
        print('Value of D: ',str(int(bv_result)))
        print('')

    else:
        print("No multiplicative inverse in this case")     # THIS WILL PRINT WHEN THERE IS NO POSSIBILITY FOR THE INVERSE NUMBER OF THE PUBLIC KEY 'E'

    d = bv_result.intValue()
    d_iv = BitVector(intVal = d)
    print('BitVector representation of Private key D:', d_iv)

    return ((e, n), (d, n))


'''
encrypt(,)
THIS FUNCTION WILL ENCRYPT THE MESSAGE THAT HAS BEEN PASSED BY THE USER

'''

def encrypt(pk, plaintext_bv):

    key_bv, n_bv = pk               # Unpack the key into it's components

    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [pow(ord(char), key_bv, n_bv) for char in plaintext_bv]

    return cipher


'''
decrypt(,)
THIS FUNCTION WILL DECRYPT THE CIPHERTEXT THAT HAS BEEN CREATED BY THE ENCRYPT FUNCTION ABOVE

'''

def decrypt(pk, ciphertext):

    key, n = pk                     # Unpack the key into its components

    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr(pow(char, key, n)) for char in ciphertext]


    return ''.join(plain)           # Return the array of bytes as a string

'''
'__main__'      -- THIS IS OUR MAIN FUNCTION
                -- EXECUTION OF THE PROGRAM WILL START FROM HERE

'''

if __name__ == '__main__':

    print('Generating First Prime Number of 1024 bits . . . . ')
    p = primes()
    print('First Prime Number is P: ',p)
    print('')

    p_bv = BitVector(intVal=p)      # CREATING THE BITVECTOR FOR PRIME NUMBER 'P'
    print('BitVector Representation of P: ',p_bv)
    print('')
    print('')
    print('')

    print('Generating Second Prime Number of 1024 bits . . . . ')
    q = primes()
    print('Second Prime Number is Q: ', q)
    print('')
    q_bv = BitVector(intVal=q)
    print('BitVector Representation of Q: ',q_bv)
    print('')
    print('')
    print('')

    print("Generating Public and Private keys for the Encryption and Decryption. . .")
    public = BitVector(size=0)      # CREATING BITVECTOR FOR THE PUBLIC AND PRIVATE KEY
    private = BitVector(size=0)

    public,private =generate_keypair(p_bv, q_bv)
    print('')

    print("Your public key is ", public)
    print('')
    print('')
    print("Your private key is ", private)
    print('')
    print('')

    message = input("Enter a message to encrypt with your public key: ")
    print('')

    encrypted_msg = encrypt(public, message)
    print('Your Encrypted message is: ')
    print(''.join(map(lambda x: str(x),encrypted_msg)))
    print('')

    print("Decrypting message with private key ", private, " . . .")
    print("Your Plaintext is:")
    print(decrypt(private, encrypted_msg))