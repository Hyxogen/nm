#!/usr/bin/bash
MINE=./ft_nm
THERIS=nm

test_one() {
	$MINE $@ > mine.txt
	LC_COLLATE=C nm $@ > theirs.txt

	diff --color=auto mine.txt theirs.txt

	if [ $? -eq 0 ]; then
		echo "OK"
	else
		echo "KO $@"
	fi
}

test_options() {
	test_one $@
	test_one -a $@
	test_one -p $@
	test_one -u $@
	test_one -g $@
	test_one -r $@
	test_one -ap $@
	test_one -au $@
	test_one -ag $@
	test_one -ar $@
}

if [ "$#" -eq 0 ]; then
	nasm -felf64 test.asm -o test.o
	test_options test.o

	nasm -felf32 test.asm -o test.o
	test_options test.o

	test_options "$MINE"
else
	test_one $@
fi
