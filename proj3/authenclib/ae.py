import os
from os import urandom
import blowfish
import copy

#
# ae.py
#
# using blowfish, various authenticated encryptions
#
# author bjr:
# date: 18 feb 2018
# last update: 21 mar 2018
#

# see https://pypi.python.org/pypi/blowfish for blowfish documentation

class Blowfish:

	def __init__(self,key):
		self.cipher = blowfish.Cipher(key)
		self.block_size = 8
	
	def encrypt(self,m):
		assert (len(m)==self.block_size)
		return self.cipher.encrypt_block(m)
	
	def decrypt(self,c):
		assert (len(c)==self.block_size)
		return self.cipher.decrypt_block(c)

class AuthEncrypt:

	def __init__(self, key_auth, key_encrypt):
		self.prf_enc = Blowfish(key_encrypt)
		self.prf_auth = Blowfish(key_auth)
		self.block_size = 8

	def pad_add(self,m):
		# given byte array m,
		# add padding
		#must copy otherwise python edits memory, and m will keep getting extra padding
		mp = copy.copy(m)
		x = self.block_size-(len(mp) % self.block_size)
		if (x == 0):
			mp += bytes([self.block_size])
			while ((len(mp)) % self.block_size !=0):
				mp += bytes([self.block_size])
		else:
			for i in range(0, x):
				mp += bytes([x])
		return mp

	def pad_rem(self,mp):
		# given a byte array mp, presumably padded,
		# remove padding
		mp_len = len(mp)
		x = mp[mp_len-1]
		for i in range(mp_len-1-x, mp_len-1):
			mp.remove(x)

		return mp

	def pad_check(self,mp):
		# given a byte array mp, presumably padded,
		# return True if correct padded, else return False

		#check last byte
		x = mp[len(mp)-1]

		for i in range(len(mp)-1, (len(mp)-1-x), -1):
			if mp[i] != x:
				return False

		return True
	
	def equal_macs(self, m1, m2):
		for x in range(0, self.block_size):
			if (m1[x] != m2[x]):
				return False
		return True

	def cbc_mac(self,m):
		# given a byte array m, a multiple of block size,
		# calculate the cbc mac.
		# neither adds nor removes padding or an IV
		assert (len(m)%self.block_size) == 0
		mp, m = m[0:self.block_size], m[self.block_size:]
		mp = self.prf_auth.encrypt(mp)
		while (len(m) > 0):
			xored_b = bytearray(self.block_size)
			mb, m = m[0:self.block_size], m[self.block_size:]
			for x in range(0, self.block_size):
				xored_b[x] = mb[x] ^ mp[x]
				mp = xored_b
				mp = self.prf_auth.encrypt(mp)

		return mp

	def cbc_encrypt(self,m):
		# given a byte array m, a multiple of block size,
		# encrypt using cbc mode
		# the first block size bytes of the encrypted message 
		# will be the IV
		# neither adds nor removes padding
		assert (len(m)%self.block_size) == 0
		iv = urandom(self.block_size)
		c = bytes(0)
		mp = bytes(0)
		mp = iv[0:self.block_size]
		c += mp

		while (len(m) > 0):
			xored_b = bytes(0)
			mb, m = m[0:self.block_size], m[self.block_size:]
			for x in range(0, self.block_size):
				xored_b += bytes([(mb[x]^mp[x])])
			mp = self.prf_enc.encrypt(xored_b)
			c += mp
		return c

	def cbc_decrypt(self,c):
		# given a byte array c, a multiple of block size,
		# decrypt using cbc mode.
		# the first block size bytes is the IV
		# neither adds nor removes padding
		assert (len(c)%self.block_size) == 0
		iv, c = c[0:self.block_size], c[self.block_size:]

		m = bytes(0)
		cp = iv
		while len(c)>0:
			xored_b = bytes(0)
			cb, c = c[0:self.block_size], c[self.block_size:]
			#cb = self.prf_enc.decrypt(cb)
			for x in range(0, self.block_size):
				xored_b += bytes([self.prf_enc.decrypt(cb)[x]^cp[x]])
			m += xored_b
			cp = cb
		return m
	
	def encrypt_cbc_none(self,m):
		#	given bytes of plaintext m, 
		#	return cbc encrypted ciphertext
		#	routine must pad
		mp = self.pad_add(m)
		c = bytes(0)
		c = self.cbc_encrypt(mp)

		return bytearray(c)
		
	def decrypt_cbc_none(self,c):
		# given cbc encrypted ciphertext c,
		# return decrypted text
		# routine must check and remove pad
		m = bytes(0)
		m = self.cbc_decrypt(c)
		if (self.pad_check(m) == False):
			return b"P"
		m_final = self.pad_rem(bytearray(m))
		return bytearray(m_final)

	def encrypt_cbc_mae(self,m):
		# given bytes of plaintext m, 
		# return mac-and-encrypt ciphertext
		# routine must pad and mac
		mp = self.pad_add(m)
		c = bytes(0)
		c = self.cbc_encrypt(mp)
		mac = self.cbc_mac(mp)
		c += mac
		return c
		
	def decrypt_cbc_mae(self,c):
		# given mac-and-encrypt ciphertext c,
		# return decrypted text (or error)
		# routine must check and remove mac and padding
		c_no_mac = c[0:len(c)-self.block_size]
		mac = c[len(c)-self.block_size: len(c)]
		mp = bytes(0)
		mp = self.cbc_decrypt(bytearray(c_no_mac))
		test_mac = self.cbc_mac(mp)

		if (self.pad_check(mp) == False):
			return b"P"

		m = self.pad_rem(bytearray(mp))

		if (self.equal_macs(test_mac, mac)):
			return m
		else:
			return b"A"
		
	def encrypt_cbc_mte(self, m):
		# given bytes of  plaintext m, 
		# return mac-then-encrypt ciphertext
		# routine must pad and mac
		mp = self.pad_add(m)
		mac = self.cbc_mac(mp)
		mp += mac
		c = bytes(0)
		c = self.cbc_encrypt(mp)
		return c
		
	def decrypt_cbc_mte(self, c):
		# given mac-then-encrypt ciphertext c,
		# return decrypted text (or error)
		# routine must check and remove mac and padding
		m = self.cbc_decrypt(c)
		m_no_mac = m[0:len(m)-self.block_size]
		mac = m[len(m)-self.block_size: len(m)]
		test_mac = self.cbc_mac(m_no_mac)

		if (self.pad_check(m_no_mac) == False):
			return b"P"

		m_final = self.pad_rem(bytearray(m_no_mac))

		if (self.equal_macs(test_mac, mac)):
			return m_final
		else:
			return b"A"

	def encrypt_cbc_etm(self, m):
		# given bytes of plaintext m, 
		# return encrypt-then-mac ciphertext
		# routine must pad and mac
		mp = self.pad_add(m)
		c = self.cbc_encrypt(mp)
		mac = self.cbc_mac(c)
		c += mac
		return c

	def decrypt_cbc_etm(self, c):
		# given encrypt-then-mac ciphertext c,
		# return decrypted text (or error)
		# routine must check and remove mac and padding
		c_no_mac = c[0:len(c)-self.block_size]
		mac = c[len(c)-self.block_size: len(c)]
		test_mac = self.cbc_mac(c_no_mac)
		m = self.cbc_decrypt(c_no_mac)

		if (self.pad_check(m) == False):
			return b"P"

		m_final = self.pad_rem(bytearray(m))

		if (self.equal_macs(test_mac, mac)):
			return m_final
		else:
			return b"A"
	
