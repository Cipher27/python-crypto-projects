from os import urandom
import numpy.random as random
from sympy.ntheory import isprime
from fractions import gcd
import numpy as np
import math

#	rsa-tasks.py
#	project 4, problem 1, csc507.182
#	template author: bjr
#	date of template: 29 march 2018
#
#	--student information--
#	name:Conor Murray
#	date: 4/11/18
#



class MyMod:

	def __init__(self,modulus):
		self.modulus = modulus

	def __repr__(self):
		return "class MyMod:\n\tn={}".format(self.modulus)

	def pow(self,a,b):
		return pow(a,b,self.modulus)
		
	def add(self,a,b):
		return (a+b)%self.modulus
		
	def mult(self,a,b):
		return (a*b)%self.modulus
		
# finish the implementation of MyMod with invert and isinvert.

# To compute x^y under modulo m
	def power(self, x, y, m) :
		if (y == 0) :
			return 1
		p = self.power(x, y // 2, m) % m
		p = (p * p) % m
		if(y % 2 == 0) :
			return p 
		else : 
			return ((x * p) % m)

	def invert(self,x):
		d,s,t = xgcd(self.modulus, x)
		if (d == 1):
			return  (t % self.modulus)
		else:
			return 0
		
	def isinvert(self,x):
		r = False # or true, depending on x and modulus
		if (self.invert(x)) != 0:
			r = True
		return r


def xgcd_aux(a,b):

	# give non-negative a, b, a>=b, return d, s and t, such that
	# d = gcd(a,b), and d = s*a + t*b
	d = 0 # should be the gcd
	s = 0 # should be a multiplier for a
	t = 0 # should be a multiplier for b
	x0, x1, y0, y1 = 1, 0, 0, 1
	while a != 0:
		q, b, a = b // a, a, b % a
		x0, x1 = x1, x0 - q * x1
		y0, y1 = y1, y0 - q * y1
	d = b
	t = x0
	s = y0
	return d, s, t

def xgcd(b,a):
	if b>a:
		d,s,t = xgcd_aux(b,a)
	else:
		d,t,s = xgcd_aux(a,b)
	assert(d == b*s+a*t)
	return d,s,t

def gcd(a,b):
	return xgcd(a,b)[0]



# *** your RSA function


class RSA:

	def __init__(self,k_bytes):
		self.k_bytes = k_bytes
		self.n, self.e, self.d = 0, 0, 0
		self.rsa_keygen(k_bytes) # sets n, e and d

	def __repr__(self):
		return "class RSA:\n\tn={}\n\te={}\n\td={}\n\tbytes={}".format(self.n, 
			self.e, self.d, self.k_bytes)

	def get_params(self):
		return(self.n,self.e,self.d)

	def rsa_keygen(self,n_digits):
		p = random_prime(n_digits)
		q = random_prime(n_digits+1)
		return self.rsa_set_primes(p,q)

	def rsa_set_primes(self,p,q):

#	****
#	set self.n, self.e and self.d
#	****
		if (not isprime(p)) or (not isprime(q)):
			return False
		self.n = p * q
		lcm = ((p-1)*(q-1))
		e = 3     
		d = 1
		mymod = MyMod(lcm)
		while (mymod.isinvert(e) == False):
			e += 1
		self.e = e
		self.d = mymod.invert(e)
		return True


	def rsa_enc(self,m):
	
#	****
#	return the encryption of message m
#	***
		#c = bytearray()
		#for x in len(str(m)):
		return (pow(m, self.e, self.n))


	def rsa_dec(self,c):
	
#	****
#	return the decryption of ciphertest c
#	***		
		#m = bytearray()
		#for x in len(str(c)):

		return (pow(c, self.d, self.n))



# *** your Miller Rabin and Pollard Rho

def miller_rabin(n,t):

# return False is no witness if found after t trials 
# else if witness is found, return
# ("factor",d) where d is a non-trivial factor of n or
# ("fermat",w) where w^(n-1) mod n does not equal 1
	mymod = MyMod(n)
	d = n-1
	r = 0
	while(d % 2 == 0):
		d = d//2
		r += 1
	assert (n-1 == d*(2**r))
	for i in range(t):
		x = (random_long_int_sizeof(n) % (n-2))+2
		if (n % x == 0):
			return ("factor", x)
		#x = pow(x,d,n)
		if (x == 1 or x == n-1):
			continue
		for j in range(r):
			if (x == n-1):
				break 
			x_old = x
			x = pow(x,2,n)
			if (x==1):
				return ("factor", math.gcd(n, x_old+1))

		y = pow(x, d, n)
		if (y != 1):
			return ("fermat", x)

	return False


def p_rho_function(x,n):
	return (pow(x,2,n)+1)%n

def pollard_rho(n,verbose=0):
	f = p_rho_function
	limit = math.sqrt(n)
	x = random_long_int_sizeof(n/2)
	x_p = x
	d = 1
	while (d == 1):
		x = f(x,n)
		x_p = f(f(x_p,n),n)
		gcd = math.gcd(x-x_p, n)
		d = gcd
			# return d, a non-trivial factor of n, or False if no non-trivial factor found.
			# the rho algorithm can be stopped after square root of n steps
	if (d != n):
		return d
	else:
		return False

# ***************************

# *** test functions

def random_long_int(k_bytes):

	k_bytes = k_bytes if k_bytes>0 else 1
	r_b = np.random.bytes(k_bytes)
	one = bytearray(1)
	one[0] = 1
	r_b += one
	return int.from_bytes(r_b, 'little')

def random_long_int_sizeof(r):
	k = int(math.log(r,2)/8)
	return random_long_int(k)

def random_prime(k_bytes):
	p_p = random_long_int(k_bytes)
	p_p = 2*p_p + 1 
	while not isprime(p_p):
		p_p += 2
	return p_p


def number_thy_test():

	print('xgcd tests')
	for i in range(30):
		g = random_long_int(5)
		a = random_long_int(5)
		b = random_long_int(5)
		(d,s,t) = xgcd(g*a,g*b)
		assert (d==(g*a*s+g*b*t))
		
	print('inversion tests')
	for i in range(30):
		p = random_prime(5)
		mod_p = MyMod(p)
		x = random_long_int_sizeof(p)
		x_inv = mod_p.invert(x)
		if x_inv!=0:
			assert (mod_p.mult(x,x_inv)==1)
			
	print("number theory passes all tests")
	return True
	


def miller_rabin_test(k_bytes, verbose=0):

	print("random primes")
	for i in range(1000):
		n = random_long_int(k_bytes)
		mr_r = miller_rabin(n,20)
		if verbose: print(mr_r)
		assert(isprime(n)!=bool(mr_r))
		if mr_r:
			if mr_r[0]=='factor':
				assert (n%mr_r[1]==0)
			elif mr_r[0]=='fermat':
				mod_n = MyMod(n)
				assert mod_n.pow(mr_r[1],n-1)!=1

	print("carmichael numbers")
	carmichael = [5*13*17,2821,8911,561]
	for n in carmichael:
		mr_r = miller_rabin(n,20)
		assert(mr_r)
		if verbose: print(mr_r)


	print("miller rabin passes all tests")
	return True



def rsa_test(rsa,trials):

	n,e,d = rsa.get_params()

	for i in range(trials):
		m = random_long_int_sizeof(n)
		c = rsa.rsa_enc(m)
		m_dec = rsa.rsa_dec(c)

		if m_dec != m:
			print(m,m_dec)
			return False

	print("rsa passses all tests")
	return True


def pollard_rho_test():
	for i in range(2,5):
		p = random_prime(i)
		q = random_prime(10)
		print("attempt to factor {}".format(p*q))
		assert(p==pollard_rho(p*q))
	print("pollard rho passes all tests")	


def run_all_tests():

	number_thy_test()
	miller_rabin_test(10)
	rsa_test(RSA(10),1000)
	pollard_rho_test()


def run_challenge():
	n=13281020721221343268485383549533965497
	e=7
	cipher= 5902234696191027616157510009783082557
	
	# factor n, then call rsa_set_primes and 
	# decrypt the cipher
	p = pollard_rho(n)
	
	rsa = RSA(10)
	rsa.rsa_set_primes(p,n//p)
	secret = rsa.rsa_dec(cipher)
	print("challenge result:\t{}".format(secret))
	return True


# *** run the tests
run_all_tests()
run_challenge()



