#
# makefile for csc507 term 182 (spring 2017-2018)
#
# author: bjr
# created: 19 feb 2018
# last-update:
#


TA= gettysburg.txt
PA= __the_passphrase__
AE= authencrypt.py
PY= python3
MF= Makefile


test:
#	make -f ${MF} refresh-ref
#	make -f ${MF} test-ref
	make -f ${MF} capture-ref
	make -f ${MF} test-ref
	make -f ${MF} clean
	
	
test-prob2:
	${PY} basic-attacks.py

test-ref:
	cat ref-none.out | ${PY} ${AE} -a none -d ${PA} > test.out
	-cmp ${TA} test.out
	cat ref-mae.out | ${PY} ${AE} -a mae -d ${PA} > test.out
	-cmp ${TA} test.out
	cat ref-mte.out | ${PY} ${AE} -a mte -d ${PA} > test.out
	-cmp ${TA} test.out
	cat ref-etm.out | ${PY} ${AE} -a etm -d ${PA} > test.out
	-cmp ${TA} test.out

capture-ref:
	cat ${TA} | ${PY} ${AE} -a none ${PA} > ref-none.out
	cat ${TA} | ${PY} ${AE} -a mae ${PA} > ref-mae.out
	cat ${TA} | ${PY} ${AE} -a mte ${PA} > ref-mte.out
	cat ${TA} | ${PY} ${AE} -a etm ${PA} > ref-etm.out
	
refresh-ref:
	-cp ../../class/proj3/gettysburg.txt .
	-cp ../../class/proj3/ref-none.out .
	-cp ../../class/proj3/ref-mte.out .
	-cp ../../class/proj3/ref-etm.out .
	

clean:
	-rm test.out ref-none.out ref-etm.out ref-mte.out ref-mae.out
	
install:
	echo "check which pip refers to Anaconda installation"
	pip install blowfish
	
