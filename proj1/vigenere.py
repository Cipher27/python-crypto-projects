import sys
import string
import os
import argparse

LETTERS_PER_GROUP_MAX = 5
GROUPS_PER_LINE_MAX = 5

def parse_args():
	parser = argparse.ArgumentParser(description="Encrypt/decrypt stdin by a shift cipher. Ignores any character other than alphabetic.")
	parser.add_argument("-k", "--key", action="store", help="The key for the cipher")
	parser.add_argument("-d", "--decrypt", action="store_true", help="decrypt, instead of encrypting")
	parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
	return parser.parse_args()

args = parse_args()

def char_shift(c,n):
	if (args.decrypt):
		i = ord(c) - ord('A')
		i = (i - n)%26
		return chr(ord('a')+i)
	else:
		i = ord(c) - ord('a')
		i = (i + n)%26
		return chr(ord('A')+i)


def execute_cipher():
	final_cipher_text = ""
	key_index = 0
	letter_count = 0
	line_group_count = 0
	for line in sys.stdin:
		for c in line:
			if c.isalpha():
				if (args.decrypt == False):
					ch = char_shift(c.lower(), ord(args.key[key_index].lower())- ord('a'))
				else:
					ch = char_shift(c.upper(), ord(args.key[key_index].upper())- ord('A'))
				if (key_index >= len(args.key)-1):
					key_index = 0
				else:
					key_index += 1

				if (letter_count == LETTERS_PER_GROUP_MAX):
					final_cipher_text += " "
					line_group_count += 1
					letter_count = 0
				if (line_group_count == GROUPS_PER_LINE_MAX):
					final_cipher_text += '\n'
					line_group_count = 0
					letter_count = 0
				final_cipher_text += ch
				letter_count += 1

	return final_cipher_text

def main():
	#Validate required params
	if (args.key == None):
		print "You must provide a key for the cipher."
		exit()
	if (sys.stdin.isatty()):
		print "This program (en/de)crypts based on the stdin, please provide a messsage to the stdin."
		exit()

	cipher = execute_cipher()
	print cipher

if __name__== "__main__":
	main()
