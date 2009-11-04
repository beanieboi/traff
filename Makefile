CC = gcc

# fuer IBM auskommentieren
#CFLAGS= -Wall -DHAVE_IBM
#LFLAGS= -lcurses

# Directories
BINDIR = /usr/local/sbin
ETCDIR = /etc

# fuer i386 auskommentieren
CFLAGS = -g -D_REENTRANT -DwithMYSQL -DwithPGSQL -Wall

LFLAGS = -lpcap -lpthread -lpq -lmysqlclient

MODULES = traff.o readconfig.o ip_table.o

EXECUTABLE = traff

default: all

all: traff

traff :	$(MODULES)
	$(CC) $(CFLAGS) $(MODULES) -o $(EXECUTABLE) $(LFLAGS)

install : 
	install -m 755 traff traff_mysql_dump traff_stdout_dump $(BINDIR)
	if ! test -e $(ETCDIR)/traff.conf; then  install -m 550 traff.conf $(ETCDIR); fi
	install -m 755 traff.initd $(ETCDIR)/init.d/traff;

traff.o      : traff.c 
readconfig.o : readconfig.c
ip_table.o   : ip_table.c

clean :
	rm -f *~
	rm -f $(MODULES) $(MODULES_STDOUT) $(MODULES_MYSQL) $(MODULES_PGSQL)
	rm -f $(EXECUTABLE) $(EXECUTABLE_STDOUT) $(EXECUTABLE_MYSQL) $(EXECUTABLE_PGSQL)
