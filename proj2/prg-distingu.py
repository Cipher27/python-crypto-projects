
# Distinguishability Experiment
# CSC507/609 Term 182
#
# Write an adversary with an advantage in the
# indistinguishability game for a vernon cipher,
# and use that adversary as an oracle to gain
# an advantage in the distinguishability game for
# a (weak) pseudorandom generator.
#
# template author: bjr
# template date: 4 feb 2018


# please enter name and date:
# student name: Conor Murray
# date (last update): 2/26/18


from __future__ import print_function
import math
import numpy.random as random
import numpy as np



### Random and LFSR pseudo-random generators

def gen_lfsr(key, tap_a, tap_b):
	#
	# master LFSR generation function
	#
	# tap_a > tap_b, 
	# (tap_a+1) is register length
	# key must be non-zero
	#
	s = np.zeros(1,dtype=np.ubyte)
	mask = (1<<(tap_a+1))-1
	s[0] = key
	while 1:
		yield 1&s[0]
		s[0] = (s[0]<<1)|(0x01 & ((s[0]>>tap_a) ^ (s[0]>>tap_b)))
		s[0] &= mask


def gen_lfsr_A(key):
	TAP_A = 5 # tap at bit 6
	TAP_B = 0 # tap at bit 1
	return gen_lfsr(key,TAP_A,TAP_B)


def gen_lfsr_S(key):
	TAP_A = 4 # tap at bit 5
	TAP_B = 2 # tap at bit 3
	return gen_lfsr(key,TAP_A,TAP_B)


def gen_lfsr_T(key):
	TAP_A = 4 # tap at bit 5
	TAP_B = 1 # tap at bit 2
	return gen_lfsr(key,TAP_A,TAP_B)


def gen_lfsr_B(key):
	g_a = gen_lfsr_A(key)
	g_s = gen_lfsr_S(key)
	g_t = gen_lfsr_T(key)
	while 1:
		a = next(g_a)
		if a&1:
			yield next(g_s)
		else:
			yield next(g_t)


def gen_random(key):
	# create a generator compatible with the LFSR generators
	# from the python random PRG. 
	# Ignores key.
	s = np.zeros(1,dtype=np.ubyte)
	while 1:
		s[0] = random.choice(2)
		yield s[0]



### Encipherment functions and key generator functions

def vernon_g(p,g):
	#
	# vernon cipher
	#
	# p is plain text as a ndarray of ubytes
	# g is a random bit generator
	# plain text length must be a multiple of 8
	#
	len = p.size
	c = np.zeros(len,dtype=np.ubyte)
	pad = 0
	for i in range(len):
		#
# replace next line
		pad = next(g)
		c[i] = p[i] ^ pad
		#
	return c


def gen_vernon_key(n):
	# key generation function for the vernon cipher
	# with key size n
	return random.choice(1<<n)


def vernon_g_test():
# your vernon cipher should pass this test
	pt = np.array([1,2,3,4,5,6,7,8],dtype=np.ubyte)
	key = gen_vernon_key(6)
	g = gen_lfsr_B(key)
	ct = vernon_g(pt,g)
	g = gen_lfsr_B(key)
	pt_x = vernon_g(ct,g)
	print ("\nvernon_g_test:")
	print ("\tkey:",key)
	print ("\tplaintext:",pt)
	print ("\tciphertext:", ct)
	print ("\tcheck:",np.array_equal(pt_x,pt))


### Indistinguishability adversary (against cipher)


def gen_bit():
	return random.choice(2)


def adversary_challenge():
	# adversary chooses a message pair
# replace next line
	m0 = np.ones(8, dtype=np.ubyte)
# replace next line
	m1 = random.randint(100, size=8,dtype=np.ubyte)
	return (m0,m1)


def adversary_decision(m0,m1,c):
	# adversary takes the encryption c of
	# either m0 or m1 and returns a best
	# guess of which message was encrypted
	#
	# This code is highly dependent on the
	# cipher used. It is the heart of the crack.
	#
# replace next line
	k0_zero_count = 0
	k0_one_count = 0
	k1_zero_count = 0
	k1_one_count = 0
	k0 = np.zeros(len(m0), dtype=np.ubyte)
	k1 = np.zeros(len(m1), dtype=np.ubyte)
	for i in range(0,len(c)):
		k0[i] = c[i] ^ m0[i]
		k1[i] = c[i] ^ m1[i]
		for y in range(1,9):
			#Count number of 0s and 1s in bits of byte stream
			if (k0[i] & y == 0):
				k0_zero_count += 1
			elif (k0[i] & y != 0):
				k0_one_count += 1
			if (k1[i] & y == 0):
				k1_zero_count += 1
			elif (k1[i] & y != 0):
				k1_one_count += 1
	#The bigger the difference, the farther from uniform distribution, hopefully?
	if (abs(k0_zero_count - k0_one_count) > abs(k1_zero_count - k1_one_count)):
		guess = 0
	else:
		guess = 1
	#
	return guess

def adversary_sample(gen_given,key_len_given):
	# the adversarial indistinguishability experiment
	# adversary presents message pair
	ch = adversary_challenge()
	# a bit is chosen at random
# replace next line
	b = gen_bit()
	# a cipher key is chosen at random
# replace next line
	key = gen_vernon_key(key_len_given)
	# the cipher answers with the cipher text
	# I will do these next two lines becah
	g = gen_given(key)
	c = vernon_g(ch[b],g)
	# the adversary makes its guess
# replace next line
	b_guess = adversary_decision(ch[0], ch[1], c)
	# the result is returned
	return b == b_guess
	


### Distinguisher 

def distinguisher_advantage(g1,g2,key_len,trials):
	# given two generators, g1 and g2, with the length
	# of their seeds, key_len, return the advantage to
	# distinguish g1 from g2 after the number of trials given
	c1 = 0.0
	c2 = 0.0
	for i in range(trials):
		if adversary_sample(g1,key_len):
			c1 += 1.0
	for i in range(trials):
		if adversary_sample(g2,key_len):
			c2 += 1.0
	return abs((c1-c2)/(1.0*trials))



### Test area


vernon_g_test() 

# experiment to "crack" lfsr_A using adversary to vernon(lfsr_A)
print (distinguisher_advantage(gen_random,gen_lfsr_A,6,2000))

# sanity check above exeriment
print (distinguisher_advantage(gen_lfsr_A,gen_lfsr_A,6,2000))
print (distinguisher_advantage(gen_random,gen_random,6,2000))

# other experiments for fun
print (distinguisher_advantage(gen_lfsr_A,gen_lfsr_B,6,2000))
print (distinguisher_advantage(gen_lfsr_S,gen_lfsr_T,6,2000))

# can you modify your adversary_decision to "crack" lfsr_B?
print (distinguisher_advantage(gen_random,gen_lfsr_B,6,2000))
