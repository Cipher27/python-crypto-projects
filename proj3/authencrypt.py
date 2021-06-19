import string
import sys
import os
import argparse
import numpy as np
from os import urandom
import authenclib.ae as ael


# authencrypt.py
#
# user interface for the authencrypt module
#
# author bjr:
# date: 18 feb 2018
# last update: 21 mar 2018
# 

# if padding error, decryption returns b'P'
# if authentication error, decryption returns b'A'
# except etm, check for padding error first (to enable attacks)

def parse_args():
	parser = argparse.ArgumentParser(description="Encrypt using blowfish.")
	parser.add_argument("key_phrase", help="key phrase")
	parser.add_argument("-a", "--auth", help="type of mac", choices=['none','mae','mte','etm'], default='etm')
	parser.add_argument("-m","--mode", help="encryption mode", choices=['cbc','counter'], default='cbc')
	parser.add_argument("-d", "--decrypt", action="store_true", help="decrypt")
	parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
	return parser.parse_args()

def main(argv):

	args_g = parse_args()
	
	if args_g.verbose:
		print("mode:", args_g.mode)
		print("auth:", args_g.auth)
		if args_g.decrypt:
			print("dir: decryption")
		else:
			print("dir: encryption")

	# key diversity code, from key_phrase create the encryption and the 
	# authentication keys

	key = bytes(args_g.key_phrase,'ASCII')
	bf = ael.Blowfish(key)
	key_auth = bf.encrypt(bytes([1,2,3,4,5,6,7,8]))
	key_encrypt = bf.encrypt(bytes([9,0,1,2,3,4,5,6]))
	ae = ael.AuthEncrypt(key_auth,key_encrypt)
	
	tin = bytearray(sys.stdin.buffer.read())

	if args_g.auth=='none':
		if args_g.decrypt:
			tout = ae.decrypt_cbc_none(tin)
		else:
			tout = ae.encrypt_cbc_none(tin)
	elif args_g.auth=='mae':
		if args_g.decrypt:
			tout = ae.decrypt_cbc_mae(tin)
		else:
			tout = ae.encrypt_cbc_mae(tin)
	elif args_g.auth=='mte':
		if args_g.decrypt:
			tout = ae.decrypt_cbc_mte(tin)
		else:
			tout = ae.encrypt_cbc_mte(tin)
	elif args_g.auth=='etm':
		if args_g.decrypt:
			tout = ae.decrypt_cbc_etm(tin)
		else:
			tout = ae.encrypt_cbc_etm(tin)
	
	sys.stdout.buffer.write(tout)


main(sys.argv)
