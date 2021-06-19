from os import urandom
import numpy.random as random
from sympy.ntheory import isprime
import numpy as np
import math
from sympy.ntheory.generate import prime as nthprime
from sympy.ntheory import factorint

#	dlog-tasks.py
#	project 5, csc507.182
#
#	student name:
#	date: 
#


# ***** given code ******
np.random.seed(12345)

def random_long_int(k_bytes):

	k_bytes = k_bytes if k_bytes>0 else 1
	r_b = np.random.bytes(k_bytes)
	one = bytearray(1)
	one[0] = 1
	r_b += one
	return int.from_bytes(r_b, 'little')


def random_prime(k_bytes):
	p_p = random_long_int(k_bytes)
	p_p = 2*p_p + 1 
	while not isprime(p_p):
		p_p += 2
	return p_p

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
		
	def invert(self,x):
		d,s,t = xgcd(self.modulus,x)
		if d==1:
			return (t%self.modulus)
		return 0
		
	def isinvert(self,x):
		return gcd(x,self.modulus)==1

def xgcd_aux(b, a):
	assert(b>=a)
	assert(a>=0)
	b_i = b
	a_i = a
	
	x0, x1, y0, y1 = 1, 0, 0, 1
	# L.I. b == b_i*x0 + a_i*y0
	while a != 0:
		q, b, a = b // a, a, b % a
		x0, x1 = x1, x0 - q * x1
		y0, y1 = y1, y0 - q * y1
	assert (b==(b_i*x0+a_i*y0))
	return b, x0, y0

def xgcd(b,a):
	if b>a:
		d,s,t = xgcd_aux(b,a)
	else:
		d,t,s = xgcd_aux(a,b)
	assert(d == b*s+a*t)
	return d,s,t

def xgcd_check(b,a,d,x0,y0):
	return (y0*a+x0*b == d)

def gcd(b,a):
	return xgcd(b,a)[0]

def dsa_modulus(k_bytes,verbose=False):
	pp = 4
	while not isprime(pp):
		p = [2]
		while len(p)<4:
			p1 = random_prime(k_bytes)
			if p1 not in p:
				p += [p1]
		if verbose: print (p)
		prod = 1 
		for pf in p:
			prod *= pf
		pp = (prod+1)
	assert isprime(pp), "modulus offered is not prime"
	return pp


# ****** code to write *******

# ***** 1. Generator finding 

def is_gen(g,p):
	# returns True if g is a generator of Z_p
	# else returns False
	#assert ((pow(g, p-1, p)) == 1)
	mymod = MyMod(p)
	factors = factorint(p-1)
	for i in factors:
		if (((p-1) % i) == 0) and (mymod.pow(g, (p-1)//i) == 1):
			return False
	
	# your code here 
	return True

def find_gen(p):
	#go from 1 to 100, isgen 1..2..3... with p?
	# given a prime p, return a generator of the Z_p
	gen = 0
	for x in range(1, 100):
		if (is_gen(x,p)):
			gen = x
			break
	# your code here
	return gen

# ****** 2. Chinese Remainder 


def chinese_remainder_aux(x,n,y,m,verbose=False):
	# for (n,m)==1, return z s.t. 
	# z=x mod n, z=y mod m
	mymod_m = MyMod(m)
	mymod_n = MyMod(n)
	n_p = mymod_n.invert(m)
	m_p = mymod_m.invert(n)

	# z = x * m * n' + y * n * m'
	z = x * m * n_p + y * n * m_p
	# where n' = m^{-1} (n)
	# where m' = n^{-1} (m)
	# your code here
	return z % (n*m)

def chinese_remainder(mods,verbose=False):
	# mods is a dict modulus -> remainder
	x = 0
	n = 0
	firstTime = True
	for i in mods:
		if (firstTime):
			n = i
			x = mods[i]
			firstTime = False
		else:
			x = chinese_remainder_aux(x, n, mods[i], i)
			n = i
	return x


# ***** 3. Pohlig-Hellman algorithm

def pohlig_hellman_aux(x,g,p):

	# given g, a generator of Z_p, and an element x of Z_p^*
	# return a dictionary of { p_i:j_i } where p_i is each
	# prime dividing (p-1), and j_i is discrete log of x mod p_i.
	result = {}
	factors = factorint(p-1)
	for f in factors:
		q = (p-1)//f
		x_q = pow(x, q, p)
		g_q = pow(g, q, p)
		for y in range(f):
			if (pow(g_q, y, p) == x_q):
				result[f] = y
				break
	# your code here
	return result # a dictionary of prime->index pairs

def check_idx_mod(idx,idx_mod):
	for p in idx_mod:
		if idx%p != idx_mod[p]:
			return False
	return True

def pohlig_hellman(x,g,p):
	idx_mod = pohlig_hellman_aux(x,g,p)
	return chinese_remainder(idx_mod)



# ***** 4. Schnorr Identification Transcripts 

def verify_schnorr_ident(I,r,s,y,g,p):
	# I,r,s from the protocol
	# y the public key, g a generator of Z_p
	mymod = MyMod(p)
	y_inv = mymod.invert(y)

	a = mymod.pow(y_inv, r)
	b = mymod.pow(g, s)
	#print ("I: " + str(I) + ", a*b: " + str(a*b) + ", p: " + str(p) + ", I-ab / p: " + str ((I-a*b)/p))
	# your code here
	return (((I- a*b) % p) == 0)


def gen_schnorr_transcript(y,g,p):

	I = 0
	r = 0
	s = 0
	while (r == 0):
		r = random_long_int(2) % (p-1)
	while (s == 0):
		s = random_long_int(2) % (p-1)
	mymod = MyMod(p)
	y_inv = mymod.invert(y)
	# your code here
	a = mymod.pow(y_inv, r)
	b = mymod.pow(g, s)
	I = (a*b) % p
	return (I,r,s)


# ***** 5. Schnorr Identification Protocol Run 


def gen_schnorr_run_verifier(I,y,g,p):
	r = 0
	while r == 0:
		r = random_long_int(2) % (p-1)
	return r


def gen_schnorr_run_P1(x,y,g,p):
	mod_p = MyMod(p)
	k = 0
	while k == 0:
		k = random_long_int(2) % (p-1)
	I = mod_p.pow(g, k)
	# your code here
	return (k,I)


def gen_schnorr_run_P2(k,I,r,x,y,g,p):
	s = (r * x + k) % (p-1)
	# your code here
	return s


def gen_schnorr_run(x,y,g,p):
	k,I = gen_schnorr_run_P1(x,y,g,p)
	r = gen_schnorr_run_verifier(I,y,g,p)
	s = gen_schnorr_run_P2(k,I,r,x,y,g,p)
	return (I,r,s)


# **** test routines *****

def test_find_generator(repetition,verbose=False):
	# note: this test might not be exhaustive. a quick check
	for i in range(repetition) :
		p = dsa_modulus(1)
		g = find_gen(p)
		mod_p = MyMod(p)
		neg_one = mod_p.pow(g,(p-1)//2)
		if ((neg_one+1)%p)!=0:
			print("*** failed ***")
			return False
	print("*** passed ***")
	return True
	
def test_chinese_remainder_aux(repetition,verbose=False):
	for t in range(repetition):
		p1 = random_prime(2)
		p2 = random_prime(2)
		z = random_long_int(4)%(p1*p2)
		zcr = chinese_remainder_aux(z%p1,p1,z%p2,p2,verbose)
		if z!=zcr:
			return False
	return True

def test_chinese_remainder(repetition,verbose=False):
	print ("Chinese remainder test ...")
	for t in range(repetition):
		p1 = random_prime(2)
		p2 = random_prime(2)
		p3 = random_prime(2)
		z = random_long_int(4)%(p1*p2*p3)
		mods = { p1:(z%p1), p2:(z%p2), p3:(z%p3) }
		zcr = chinese_remainder(mods,verbose)
		if z!=zcr:
			print("*** failed ***")
			return False
	print("*** passed ***")
	return True

def test_pohlig_hellman_aux(rep,verbose=False):
	print("Pohlig-Hellman Alg test (part 1) ...")
	
	for t in range(rep):
		p = dsa_modulus(1)
		g = find_gen(p)
		mod_p = MyMod(p)
		assert isprime(p)
		assert mod_p.pow(g,p-1)==1
		
		if verbose: print("gen: {}, mod: {}".format(g,p))
		
		idx = random_long_int(2)%(p-1)
		x = mod_p.pow(g,idx)
		idx_mod = pohlig_hellman_aux(x,g,p)
		
		if verbose: print("x: {}, index by mods: {}".format(x,idx_mod))
		if not check_idx_mod(idx,idx_mod):
			print("*** failed ***")
			print("*** index under moduli not correct ***")
			return False
	print("*** passed ***")
	return True


def test_pohlig_hellman(rep,verbose=False):
	print("Pohlig-Hellman Alg test ...")
	
	for t in range(rep):
		p = dsa_modulus(1)
		g = find_gen(p)
		mod_p = MyMod(p)
		assert isprime(p)
		assert mod_p.pow(g,p-1)==1
		
		if verbose: print("gen: {}, mod: {}".format(g,p))
		
		idx = random_long_int(2)%(p-1)
		x = mod_p.pow(g,idx)
		idx_mod = pohlig_hellman_aux(x,g,p)
		idx_out = pohlig_hellman(x,g,p)
		if verbose: print("discret log of {} is {}".format(x,idx_out))
		if idx!=idx_out:
			print("*** failed ***")
			print("*** complete index not correct ***")
			return False
	print("*** passed ***")
	return True
	

def test_schnorr_gen_transcript(repetition,verbose=False):
	print("Schnorr transcript test ...")
	for i in range(repetition) :
		p = dsa_modulus(1)
		g = find_gen(p)
		mod_p = MyMod(p)
		x = random_long_int(2) % (p-1)
		y = mod_p.pow(g,x)
		(I,r,s) = gen_schnorr_transcript(y,g,p)
		if verbose : print("I: {} r: {} s: {}".format(I,r,s))
		if not verify_schnorr_ident(I,r,s,y,g,p):
			print("*** failed ***")
			return False
	print("*** passed ***")
	return True

def test_schnorr_gen_run(repetition,verbose=False):
	print("Schorr protocol run test ...")
	for i in range(repetition) :
		p = dsa_modulus(1)
		g = find_gen(p)
		mod_p = MyMod(p)
		x = random_long_int(2) % (p-1)
		y = mod_p.pow(g,x)
		(I,r,s) = gen_schnorr_run(x,y,g,p)
		if verbose : print("p: {} g: {} y: {} I: {} r: {} s: {}".format(p,g,y,I,r,s))
		if not verify_schnorr_ident(I,r,s,y,g,p):
			print("*** failed ***")
			return False
	print("*** passed ***")
	return True


def challenge_schnorr(s):
	p = 728725799
	g = 7
	I = 17502205
	r = 91579
	y = 314318115
	mymod = MyMod(p)
	s = 437296560
	
	#b = g^s mod p
	#a = mymod.pow(mymod.invert(y), r)
	#I = (a*b) % p

	#this commented code works, however does not run fast on a home-computer. Wasn't sure how to pick a good starting point besides 0
	#while (((a*mymod.pow(g,s))% p) != I):
	#	s += 2

	assert isprime(p)
	assert is_gen(g,p)
	if not verify_schnorr_ident(I,r,s,y,g,p):
		print("*** failed ***")
		return False
	print("*** passed ***")
	return True

# ***** run tests *****

verbose = True

print("Problem 1:")
assert(test_find_generator(10))
print("Problem 2:")
assert test_chinese_remainder_aux(10)
assert test_chinese_remainder(10,verbose), "test_chinese_remainder"
print("Problem 3:")
assert test_pohlig_hellman_aux(10,verbose), "test_pohlig_hellman_aux"
assert test_pohlig_hellman(10,verbose), "test_pohlig_hellman"
print("Problem 4:")
assert test_schnorr_gen_transcript(10,verbose), "test_schnoor_gen_transcript failed"
print("Problem 5:")
assert test_schnorr_gen_run(10,verbose), "test_schnorr_gen_run"
print("Challenge:")
assert challenge_schnorr(0), "challenge_schnorr"
#


# ***** END OF FILE *****

