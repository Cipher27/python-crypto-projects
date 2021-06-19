import string
import sys
import os

#
# frequency count the lowercase letters from stdin
#
# author: bjr
# date: january 2018
#

def init_letter():
    letters = dict() 
    for char in string.ascii_lowercase:
        letters[char] = 0
    return letters

def count_letters(s,d):
    # s is a string, d is an initialized dict of characters
    for c in s:
        if c in d:
            d[c] += 1
    return d

def main(argv):
    d = init_letter()
    for line in sys.stdin:
        count_letters(line,d)
    for c in sorted(d.keys()):
    	print c, d[c]

if __name__ == "__main__":
    main(sys.argv)

