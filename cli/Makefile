LEX = lex
YACC = yacc -d
CC = gcc
INSTDIR = ../bin

# parse is the final object that we will generate, it is produced by
# the GCC compiler from the y.tab.o and from the lex.yy.o

parse: y.tab.o lex.yy.o
	cp {y.tab.o,lex.yy.o}  ${INSTDIR}

lex.yy.o: lex.yy.c y.tab.h
lex.yy.o y.tab.o: parse.h

## This rule will use yacc to generate the files y.tab.c and y.tab.h
## from our file parse.y

y.tab.c y.tab.h: parse.y
	$(YACC) -v parse.y

## this is the make rule to use lex to generate the file lex.yy.c from
## our file parse.l

lex.yy.c: parse.l
	$(LEX) parse.l

clean:
	-rm -f *.o lex.yy.c *.tab.*  parse *.output
