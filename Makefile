CC = gcc

# fuer IBM auskommentieren
#CFLAGS= -Wall -DHAVE_IBM
#LFLAGS= -lcurses

# fuer i386 auskommentieren
CFLAGS= -g -D_REENTRANT
LFLAGS = -lncurses -lpcap -lpthread

MODULES = traff.o readconfig.o data.o ip_table.o
MODULES_1 = traff_stdout_dump.o readconfig.o
#MODULES_2 = fahren.o semaphore.o

EXECUTABLE = traff
EXECUTABLE_1 = traff_stdout_dump
#EXECUTABLE_2 = fahren



all: $(EXECUTABLE) $(EXECUTABLE_1)
# $(EXECUTABLE_2)

$(EXECUTABLE) :	$(MODULES)
	$(CC) $(CFLAGS) $(MODULES) -o $(EXECUTABLE) $(LFLAGS)

$(EXECUTABLE_1) :	$(MODULES_1)
	$(CC) $(CFLAGS) $(MODULES_1) -o $(EXECUTABLE_1) $(LFLAGS)

traff.o      : traff.c
readconfig.o : readconfig.c
data.o       : data.c
ip_table.o   : ip_table.c
traff_stdout_dump.o : traff_stdout_dump.c 

clean :
	rm -f *~
	rm -f $(MODULES) $(MODULES_1) $(MODULES_2)
	rm -f $(EXECUTABLE) $(EXECUTABLE_1) $(EXECUTABLE_2)
