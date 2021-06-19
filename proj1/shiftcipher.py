import string
import sys
import os
import argparse

#
# shiftcipher.py
# 
# a sample python program from doing a shift cipher
#
# author:bjr
# date: jan 2018
# last update:
#


def char_shift(c,n):
	# shift char c by n
	i = ord(c)-ord('a')
	i = (i+n)%26
	return chr(ord('A')+i)

def parse_args():
	parser = argparse.ArgumentParser(description="Encrypt/decrypt stdin by a shift cipher. Ignores any character other than alphabetic.")
	parser.add_argument("shift", type=int, help="shift amount for encrpytion")
	parser.add_argument("-d", "--decrypt", action="store_true", help="decrypt, instead of encrypting")
	parser.add_argument("-g", "--word_group", type=int, default=5, help="characters per word group")
	parser.add_argument("-G", "--line_group", type=int, default=5, help="word groups per line")
	parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
	return parser.parse_args()


def main(argv):

	args = parse_args()
	shift = args.shift%26
	if args.decrypt:
		shift = 26-shift
	i = 0
	s = ""
	r = args.word_group * args.line_group
	for line in sys.stdin:
		for c in line:
			if c.isalpha():
				c = char_shift(c.lower(),shift)
				if args.decrypt:
					c = c.lower()
				s += c
				i += 1
				if i%args.word_group==0:
					s += ' '
				if i%r==0:
					s += '\n'
	print s
	

main(sys.argv)