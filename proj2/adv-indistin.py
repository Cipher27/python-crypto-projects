#
# Adversarial Indistinguishability Experiment
# CSC507/609 Term 182
#
# Write an adversary with an advantage in the
# indistinguishability game for a vigenere cipher.
# The key is generated according to the distribution
# presented in problem 2.8 of the class text.
#
# template author: bjr
# template date: 30 jan 2018


# please enter name and date:
# student name: Conor Murray
# date (last update): 2/24/16


import string
import collections
import numpy.random as random
import numpy as np

### Encipherment and key generator functions

def vigenere_encipher(p,k):
	c = ""
	kord = [ ord(kc)-ord('a') for kc in k ]
	i = 0
	for pi in p:
		#
# replace next line
		if (pi.isalpha()):	
			index = ord(pi) - ord('a')
			shift = (index + kord[i % len(k)])%26
			c += chr(ord('a')+shift)
			i += 1
		#
	return c ;

def vigenere_decipher(c,k):
        p = ""
        kord = [ ord(kc)-ord('a') for kc in k ]
        i = 0
        for ci in c:
                #
# replace next line
                if (ci.isalpha()):
                        index = ord(ci) - ord('a')
                        shift = (index - kord[i % len(k)])%26
                        p += chr(ord('a')+shift)
                        i += 1
                #
        return p

def gen_key(n):
	return gen_key_size(random.choice(n)+1)
	
def gen_key_size(n):
	alph = [ i for i in 'abcdefghijklmnopqrstuvwxyz' ]
	s = ""
	for i in range(n):
		s += random.choice(alph) 
	return s

#ioc functions
def calc_ioc(frequencies):
        numerator = 0.0
        for x in string.ascii_lowercase:
                numerator += frequencies[x] * (frequencies[x] - 1)
        denominator = (sum(frequencies.values()) * (sum(frequencies.values())- 1))
        return numerator/denominator

def count_letter_frequency(input_string_alphabet_only):
        frequencies = collections.Counter(input_string_alphabet_only)
        return frequencies


### Adversary functions

def gen_bit():
	return random.choice(2)


def adversary_challenge():
	# adversary chooses a message pair
	#
# replace next line
	m0 = chr(ord('a')) * 100
# replace next line
	m1 = gen_key_size(100)
	#
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
	m0_p = vigenere_decipher(c, m0)
	m1_p = vigenere_decipher(c, m1)	
	m0_ioc = calc_ioc(count_letter_frequency(m0_p))
	m1_ioc = calc_ioc(count_letter_frequency(m1_p))
	if (m0_ioc > m1_ioc):
		guess = 0
	else:
		guess = 1
	#
	return guess


def adversary_start():
	# adversary chooses a message pair
	return adversary_challenge()


def adversary_sample(m):
	# the adversarial indistinguishability experiment
	# a bit is chosen at random
# replace next line
	b = gen_bit()
	#
	# a cipher key is chosen at random
# replace next line
	k = gen_key(100)
	#
	# the cipher is queried with key k and message m[b]
# replace next line
	c = vigenere_encipher(m[b], k)
	#
	# the adversary makes its guess
# replace next line
	guess = adversary_decision(m[0], m[1], c)
	#
	return b==guess


def adversary_advantage(trials):
	m = adversary_start()
	count = 0 
	for i in range(trials):
		if adversary_sample(m):
			count += 1
	return (count+0.0)/(trials+0.0)

# test area
print (adversary_advantage(1000))

