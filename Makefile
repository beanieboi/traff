CC = gcc

# fuer IBM auskommentieren
#CFLAGS= -Wall -DHAVE_IBM
#LFLAGS= -lcurses

# Directories
BINDIR = /usr/local/sbin
ETCDIR = /etc

# fuer i386 auskommentieren
CFLAGS= -g -D_REENTRANT
LFLAGS = -lpcap -lpthread
LFLAGS_MYSQL = -lmysqlclient

MODULES = traff.o readconfig.o data.o ip_table.o
MODULES_STDOUT = traff_stdout_dump.o readconfig.o
MODULES_MYSQL = traff_mysql_dump.o readconfig.o
#MODULES_2 = fahren.o semaphore.o

EXECUTABLE = traff
EXECUTABLE_STDOUT = traff_stdout_dump
EXECUTABLE_MYSQL = traff_mysql_dump
#EXECUTABLE_2 = fahren



default: all

all: traff stdout mysql 

traff :	$(MODULES)
	$(CC) $(CFLAGS) $(MODULES) -o $(EXECUTABLE) $(LFLAGS)

stdout :	$(MODULES_STDOUT)
	$(CC) $(CFLAGS) $(MODULES_STDOUT) -o $(EXECUTABLE_STDOUT) $(LFLAGS)

mysql : $(MODULES_MYSQL)
	$(CC) $(CFLAGS) $(MODULES_MYSQL) -o $(EXECUTABLE_MYSQL) $(LFLAGS_MYSQL)

install : 
	install -m 755 traff traff_mysql_dump traff_stdout_dump $(BINDIR)
	if ! test -e $(ETCDIR)/traff.conf; then  install -m 550 traff.conf $(ETCDIR); fi
	install -m 755 traff.initd $(ETCDIR)/init.d/traff;

traff.o      : traff.c
readconfig.o : readconfig.c
data.o       : data.c
ip_table.o   : ip_table.c
traff_stdout_dump.o : traff_stdout_dump.c 

clean :
	rm -f *~
	rm -f $(MODULES) $(MODULES_STDOUT) $(MODULES_MYSQL)
	rm -f $(EXECUTABLE) $(EXECUTABLE_STDOUT) $(EXECUTABLE_MYSQL)
