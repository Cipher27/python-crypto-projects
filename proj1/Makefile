#
# makefile for python and jupyter
# trying to work both in the notebook and the command line
# the run target should trigger jupyter nbconvert, and run
# the result

S= obama-sotu
V= vigenere
I= ioc
C= crack-vigenere
T= gettysburg
K= notsosecret

test:
	make test-enc
	make test-dec
	make test-guess-length
	make test-guess-key

test-enc:
	cat $T.txt | python $V.py -k $K

test-dec:
	cat $T.txt | python $V.py -k $K | python $V.py -k $K -d

test-guess-length:
	cat $T.txt | python $V.py -k $K | python $I.py

test-guess-key:
	cat $T.txt | python $V.py -k $K | python $C.py -l `cat $T.txt | python $V.py -k $K | python $I.py` -s "`cat $S.txt`"
