import sys
import os
import array
import collections
import re
import string
import argparse

KEY_LENGTH_CAP = 40
APPROX_ENGLISH_LANGUAGE_IOC = 0.067

def parse_args():
	parser = argparse.ArgumentParser(description="Guesses key length for Vigenere cipher.")
	parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
	return parser.parse_args()

args = parse_args()

def count_letter_frequency(input_string_alphabet_only):
	frequencies = collections.Counter(input_string_alphabet_only)
	return frequencies

def compile_cipher_sequence(input_string_alphabet_only, offset, start):
	sequence = ""
	for x in range(start, len(input_string_alphabet_only)):
		if (x % offset == 0):
			sequence += input_string_alphabet_only[x]
	return sequence

def calc_ioc(frequencies):
	numerator = 0.0
	for x in string.ascii_uppercase:
		numerator += frequencies[x] * (frequencies[x] - 1)
	denominator = (sum(frequencies.values()) * (sum(frequencies.values())- 1))
	return numerator/denominator

def take_a_guess(cipher_text):
	sequence_iocs = dict()
	best_guess = 0
	for x in range(1, KEY_LENGTH_CAP + 1):
		avg_seq_ioc = 0
		for y in range (0, x):
			sequence = compile_cipher_sequence(cipher_text, x, y)
			frequency = count_letter_frequency(sequence)
			ioc = calc_ioc(frequency)
			avg_seq_ioc += ioc
		avg_seq_ioc /= x
		sequence_iocs[x] = avg_seq_ioc

	if (args.verbose):
		print "key_length: avg IOC"
		for x in sequence_iocs.keys():
			print "" + str(x) + ": " + str(sequence_iocs[x])
		print ""

	for x in sorted(sequence_iocs.keys()):
		if sequence_iocs[x] > APPROX_ENGLISH_LANGUAGE_IOC:
			best_guess = x
			break;

	return best_guess


def main():
	#check required params
	if (sys.stdin.isatty()):
		print "This program uses the index of coincidence to guess key length of a vigenere cipher provided to the stdin, please provide a cipher to stdin."
		exit()

	stdin_only_alphabet = re.sub(r'[^a-zA-Z]+', '', sys.stdin.read())
	print take_a_guess(stdin_only_alphabet)

	#print calc_ioc(freq)

if __name__== "__main__":
	main()