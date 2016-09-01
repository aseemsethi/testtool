#
# Makefile for mont program
#

# Parameters
INSTDIR = bin
MONT = tool
CFLAGS = -g
LEX = lex
CLI_OBJS = bin/lex.yy.o bin/y.tab.o

csrc = $(wildcard common/*.c)	\
		$(wildcard bgp/*.c)		\
		$(wildcard ssl/*.c)		\
		$(wildcard ssl_perf/*.c)	\
		$(wildcard http/*.c)		\
		$(wildcard openvpn/*.c)

obj = $(csrc:.c=.o)

LDFLAGS = -Lbin -ljsmn -lexpat -lpthread -lcrypto -lssl -lcurl 
# -ll -lm

# Targets 
all : OPENSRC $(MONT)
	cp $(MONT) ${INSTDIR}

OPENSRC: 
	(mkdir -p bin)
	(cd jsmn; make all)
	(cd cli; make)

$(MONT): $(obj)
	$(CXX) -g -o $@ $^ $(CLI_OBJS) $(LDFLAGS)

clean:
	$(RM) core* ssl/*.o ssl_perf/*.o http/*.o bgp/*.o common/*.o \
		ikev2/*.o openvpn/*.o 
	$(RM) bin/parse bin/libjsmn.a bin/tool
	(cd jsmn; make clean)
	(cd cli; make clean)

