#!/usr/bin/bash
MINE=./ft_nm
THERIS=nm

$MINE $@ > mine.txt
LC_COLLATE=C nm $@ > theirs.txt

diff --color=auto mine.txt theirs.txt
