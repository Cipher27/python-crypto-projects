import sys
import collections
import argparse
import string
import re

def parse_args():
	parser = argparse.ArgumentParser(description="Guess the key of a vigenere cipher sent to stdin based on an estimated key length")
	parser.add_argument("-l", "--length", action="store", help="The length of the key for the program to guess.")
	parser.add_argument("-s", "--sample", action = "store", help="Sample text to base frequencies on (English)")
	parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
	return parser.parse_args()

args = parse_args()

def count_letter_frequency(input_string_alphabet_only):
	frequencies = collections.Counter(input_string_alphabet_only)
	return frequencies

def strip_nonalphabet(some_text):
	clean_text = re.sub(r'[^a-zA-Z]+', '', some_text)
	return clean_text

def char_shift(c,n):
	# shift char c by n
	i = ord(c.lower())-ord('a')
	i = (i+n)%26
	return chr(ord('A')+i)

def compile_cipher_sequence(input_string_alphabet_only, offset, start):
	sequence = ""
	for x in range(start, len(input_string_alphabet_only)):
		if ((x-start) % offset == 0):
			sequence += input_string_alphabet_only[x]
	return sequence

def create_english_letter_frequency_dict(sample_text):
	return_val = dict()
	freq = count_letter_frequency(sample_text)
	index = 0
	for x in string.ascii_uppercase:
		return_val[index] = float((freq[x] + freq[x.lower()]))/sum(freq.values())
		index += 1

	if (args.verbose):
		print "English Letter Frequencies based off reference text:\n"
		index = 0
		for x in range(0, 26):
			print "[" + str(x) + "] = " + str(return_val[x])
			index += 1
	return return_val

def guess_letter(expected_freq, cipher_text_sequence):
	chi_squared = dict()

	if (args.verbose):
		print "sequence to try 25 shifts for is: " + cipher_text_sequence

	#init dict
	for x in range(0, 26):
		chi_squared[x] = 0.0

	for x in string.ascii_uppercase:
		new_sequence = ""
		for i in range(0, len(cipher_text_sequence)):
			new_sequence += char_shift(cipher_text_sequence[i], ord('A') - ord(x))
		observed_letter_freq = count_letter_frequency(new_sequence)

		for y in string.ascii_uppercase:
			observed = (observed_letter_freq[y] + observed_letter_freq[y.lower()])
			expected = expected_freq[ord(y)-ord('A')] * len(new_sequence)
			numerator = (observed - expected) * (observed - expected)
			chi_squared[ord(x) - ord('A')] += (numerator/expected)

	if (args.verbose):
		print "chi squared values for cipher " + cipher_text_sequence + " are:"
		for z in range(0, 26):
			print "[" + str(z) + "]: " + str(chi_squared[z])

	lowest = 0
	for x in range(0, 26):
		if chi_squared[x] < chi_squared[lowest]:
			lowest = x
	if (args.verbose):
		print "guess letter is: " + chr(ord('A') + lowest)

	return chr(ord('a') + lowest)


def find_key(expected_freq, cipher_text, key_length):	
	key = ""
	for x in range (0, key_length):
		key += guess_letter(expected_freq, compile_cipher_sequence(cipher_text, key_length, x))
	print "" + key

def main():
	#check required params
	if (sys.stdin.isatty()):
		print "Please send a cipher text to the stdin."
		exit()
	if (args.length == None):
		print "You must provide a key length."
		exit()
	if (args.sample == None):
		print "You must provide sample text to base english frequencies on."
		exit()

	#prepare cipher text
	stdin_clean = strip_nonalphabet(sys.stdin.read())

	sample_text_clean = strip_nonalphabet(args.sample)

	if (args.verbose):
		print "Key length is: " + str(args.length)
		print "Cipher txt from stdin (alphabet only) is: " + stdin_clean
		print "Sample text to base frequencies on is: " + sample_text_clean

	expected_eng_frequencies = create_english_letter_frequency_dict(sample_text_clean)

	key = find_key(expected_eng_frequencies, stdin_clean, int(args.length))

if __name__== "__main__":
	main()