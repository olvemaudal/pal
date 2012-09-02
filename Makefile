SHELL=/bin/sh

.SUFFIXES:
.SUFFIXES: .c .cpp .o

#-D_FORTIFY_SOURCE=2 -D_GLIBCXX_DEBUG_PEDANTIC=1 -D_GLIBCX_DEBUG=1 
#CFLAGS=-std=c++98 -pedantic -Wall -Wextra -Weffc++ -g -MMD 
CFLAGS=-std=c++98 -MMD 
#CFLAGS=-std=c++98 
LDFLAGS=-g 

date = `date +"%Y%m%d%H%M"`

all: libpal.a run_tests httpget

sources = type1_message.cpp type2_message.cpp type3_message.cpp tools.cpp pal.cpp httpget.cpp tests.cpp

-include $(sources:.cpp=.d)

.cpp.o:
	g++ $(CFLAGS) -c -o $@ $<

.c.o:
	g++ $(CFLAGS) -c -o $@ $<

httpget.o: httpget.cpp
	g++ $(CFLAGS) -c -o $@ $<

httpget: httpget.o libpal.a
	g++ -o $@ $(LDFLAGS) -lcrypto $+

tests: tests.o libpal.a
	g++ -o $@ $(LDFLAGS) -lcrypto $+

dist: Makefile ntlm_message.hpp type1_message.hpp type1_message.cpp type2_message.hpp type2_message.cpp type3_message.hpp type3_message.cpp pal.hpp pal.cpp tools.hpp tools.cpp tests.cpp ntlm_ssp_flags.hpp notes.txt httpget.cpp README
	mkdir libpal-source-$(date)
	cp $+ libpal-source-$(date)
	tar czf libpal-source-$(date).tar.gz libpal-source-$(date)
	rm -rf libpal-source-$(date)

run_tests: tests
	./tests

libpal.a: pal.o type1_message.o type2_message.o type3_message.o tools.o
	rm -f $@
	ar cru $@ $+
	ranlib $@

clean:
	rm -rf *.dSYM
	rm -f httpget tests *.o *.a *.d libpal-*.tar.gz
