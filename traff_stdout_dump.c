/*****************************************************************************
 *                       main.c  -  description                              *
 *                       --------------------------------                    *
 *  begin                : Fri Jul 13 2001                                   *
 *  copyright            : (C) 2001 by Hans Marcus Kruger                    *
 *  email                : hanskruger@iname.com                              *
 *                                                                           *
 ****************************************************************************/
 
/*****************************************************************************
 *  This program is free software; you can redistribute it and/or modify     *
 *  it under the terms of the GNU General Public License as published by     *
 *  the Free Software Foundation; either version 2 of the License, or        *
 *  (at your option) any later version.                                      *
 *                                                                           *
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>
#include "readconfig.h"

void cipa(unsigned int ip, unsigned char cip[]);


//-----------------------------------------------------------------------------------
int main (int argc, char *argv[]) {
//  t_config * config = (t_config *) malloc(sizeof(t_config));
  t_cat * cat = 0;                                                                      
  int i,fifo;
  unsigned char cip[4];
  t_data data;
  extern int errno;
  //fprintf(stderr,"Fifo Filename: %s Category %s\n", argv[1],argv[2]);
 
  if ( (fifo = open(argv[1],O_RDONLY)) == -1 ) {
    fprintf(stderr, "%s: Cat: %s: Error opening fifo %s for reading.\nError: %s\n",argv[0],argv[2],argv[1],strerror(errno));
    exit(1);
  }
  while(read(fifo, &data, sizeof(t_data))) {
    cipa(data.ip, cip);
    fprintf(stdout, "%03d.%03d.%03d.%03d %d %d\n", cip[0],cip[1],cip[2],cip[3], data.input, data.output);
  }
  close(fifo);
  sleep(2);
//  unlink(argv[2]);
 
} // main
//-----------------------------------------------------------------------------------
void cipa(unsigned int ip, unsigned char cip[]) {
  cip[0] = ip>>24;
  cip[1] = ((ip<<8)>>24);
  cip[2] = ((ip<<16)>>24);
  cip[3] = ((ip<<24)>>24);
}


