import numpy.random as random
import numpy as np
from os import urandom
import authenclib.ae as ael
import copy


# basic_attacks.py
#
# template for answering problem 2 on project 3, csc507-182.
#
# author bjr:
# date: 14 march 2018
# last update: 16 march 2018
#

# this file gives a basic structure for submitting for grading the attacks
# described in project 2. the tests are at the end; you create
# attack_indistinguishability(), attack_forgery() and attack_padding()
# to make the tests true.

# helpful routines, no need to change

def gen_bit():
	return random.choice(2)

def generate_encryption():
	return ael.AuthEncrypt(urandom(8),urandom(8))

def create_challenge(ae,m):
	# the adversarial indistinguishability experiment
	b = gen_bit()
	return (b, ae.encrypt_cbc_none(m[b]))

def print_bytes(b):
	for c in b:
		print ("{:02x} ".format(c),end='')
	print("")


class PaddingChallenges:

	def __init__(self,ae):
		self.ae = ae
		
	def generate(self):
		self.msgs = ( urandom(15), urandom(14), urandom(10), urandom(8) )
		c = ( self.ae.encrypt_cbc_mae(m) for m in self.msgs )
		return c

	def verify_lastbyte_withpadding(self,m_pad):
		for m, m_org in zip(m_pad,self.msgs):
			if len(m)!=16:
				return False
			m = m[8:]
			m_org = (self.ae.pad_add(m_org))[8:]
			if m!=m_org:
				return False
		return True

	def print_msgs(self):
		for m in self.msgs:
			print_bytes(m)


# ********
# An attack against indistinguishability on the none mode using chosen ciphertext attack. 
# ********

# here is where your attack begins, by choosing two messages.

def adversary_message_pair():
	# adversary chooses a message pair
	
	# rewrite this next line, for your choice of message pair
	m0, m1 = urandom(8), urandom(8)
	
	return (m0,m1)

# here is where your attack goes next, after you get to choose messages, a
# challenge cyphertext is returned. The two steps to creating the challenge are:
# (1) choosing an encryption instance (random keys, etc) and (2) creating
# two messages, and giving them to the encryption instance to encrypt one of 
# them. NOTE: create_challenger tells you which of the two messages it 
# encrypted. The attacker is not supposed to know this value, but is to 
# try to guess it. It is returned only for the purpose of checking the attacker's
# guess.

def attack_indistinguishability():
	
	ae = generate_encryption()
	m = adversary_message_pair()
	print (m)
	b, c = create_challenge(ae,m)
	c_len = len(c)
	padding = 8
	# find padding length
	for x in range(0, ae.block_size):
		#change byte which affects x'th byte of padding block.
		#allows to find padding and thus know which message was sent
		c[c_len-(2*ae.block_size)+x] = 10
		if (ae.decrypt_cbc_none(c) == b"P"):
			break
		padding -= 1

	num = 0
	recovered_pt = bytearray(8)
	dec_msg_block = ae.prf_enc.decrypt(c[8:16])
	for x in range(0,8):
		recovered_pt[x] = dec_msg_block[x] ^ c[x]

	print (recovered_pt)

	# Approach for trying all 256 possiblities of the byte of message 
	#for i in range(0,256):
	#	ct = copy.copy(c)
	#	test_block = bytearray(8)
		#some byte i had to be xored with the last byte of the IV and encrypted to get the last byte of C0 (the msg block cipher)
	#	test_block[7] = ct[7] ^ i
	#	test_block = ae.prf_enc.encrypt(test_block)

		#so, we replace the last byte of C0 with encrypted xor of i and IV
	#	ct[15] = test_block[7]

		#if decryption is valid, and first byte is equal to n, we've found the right value
	#	if (ae.decrypt_cbc_none(ct) != b"P"):
	#		if (num)
	#		num = i
	#		break



	print (bytes([num]))
	b_guess = 1
	#if num was equal to m0s's last byte, set b_guess to 0
	if (num == m[0][7]):
		b_guess = 0

	#I feel like this should work, but it doesn't :(
	return (b==b_guess)


def bytes_to_int(bytes):
    result = 0

    for b in bytes:
        result = result * 256 + int(b)

    return result
# ********
# An attack on MAE using message extension to forge a new message out of given chosen plaintext message. 
# ********

def attack_forgery():

	# the attack begins by generating an encryption instance, than gathering two or
	# more plaintext-cipertext pairs
	
	# the following stanza is only an example; ma and mb may or may not be
	# useful in creating c_forgery. however you will be doing something similar
	# to sample the encryption in order to build the forgery
	ae = generate_encryption()
	ma, mb  = bytes(8), bytes(8)
	pad_block = bytes([8,8,8,8,8,8,8,8])
	ca = ae.encrypt_cbc_mae(ma)	
	cb = ae.encrypt_cbc_mae(mb)

	#create our "authentic" MAC
	m_fake = ma + pad_block + mb + pad_block
	fake_mac = ae.cbc_mac(m_fake)

	#want everything from CA but the MAC
	c_forgery = ca[0:24]

	#create first block of fake ciphertext
	c_f1 = bytes(0)
	for x in range(0, ae.block_size):
		c_f1 += bytes([ca[16+x] ^ mb[x]])
	c_f1 = ae.prf_enc.encrypt(c_f1)
	c_forgery += c_f1

	#create second block of fake ciphertext
	c_f2= bytes(0)
	for x in range(0, ae.block_size):
		c_f2 += bytes ([c_f1[x] ^ pad_block[x]])
	c_f2 = ae.prf_enc.encrypt(c_f2)
	c_forgery += c_f2

	c_forgery += fake_mac

	msg = ae.decrypt_cbc_mae(c_forgery)

	# is msg authentic? if it does not return a one byte error code, it is
	return len(msg)>1

# ********
# An attack to decrypt a message encrypted by MAE making use of the padding and that padding errors take precedence.
# ********

def attack_padding():

	ae = generate_encryption()
	p_c = PaddingChallenges(ae)
	ct_challenges = p_c.generate()	# a set of ciphertext challenges

	msgs = []
	for ct in ct_challenges:

		# your code here
		# the cryptotext ct is given. 
		# use a padding attack to find the message.
		# The result is in msg, including the padding bytes.

		c_len = len(ct)
		padding = 8
	# do something that uses c and m to get b_guess
		for x in range(0, ae.block_size):
			c = copy.copy(ct)
			c = bytearray(ct)
		#change byte which affects x'th byte of padding block.
		#allows to find padding and thus know which message was sent
			c[c_len-(2*ae.block_size)+x] = 10
			if (ae.decrypt_cbc_mae(c) == b"P"):
				break
			padding -= 1
		msg = bytearray(8)
		for x in range(7, 1, -1):
			num = 0
			for i in range(0, 256):
				ct_copy = copy.copy(ct)
				ct_copy = bytearray(ct_copy)
				ct_copy[x] = i
				if (ae.decrypt_cbc_mae(ct_copy) == b"A"):
					msg[x] = i
				
		print (msg)



	msgs += [msg]

	result = p_c.verify_lastbyte_withpadding(msgs)

	return result


# ********
# run attacks
# ********

print ("An attack against indistinguishability on the none mode.")
y = 0
#for x in range(0, 1000):
if attack_indistinguishability():
	print("\t*** success ***")
else:
	print("\t*** failed ***")
#print (y/1000)


print ("An attack on MAE using message extension to forge a new message.")
if attack_forgery():
	print("\t*** success ***")
else:
	print("\t*** failed ***")

	
print ("Attack a message encrypted by MAE using padding errors")
if attack_padding():
	print("\t*** success ***")
else:
	print("\t*** failed ***")

