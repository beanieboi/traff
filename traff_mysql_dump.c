/*****************************************************************************
 *  begin                : Fri Jul 13 2001                                   *
 *  copyright            : (C) 2001 by Hans Marcus Kruger                    *
 *  email                : hanskruger@iname.com                              *
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
#include <mysql/mysql.h>
#include <syslog.h>
#include "readconfig.h"
#include <signal.h>

#define QUERYLENGTH 1024
#define DEBUG(s) printf("traff_mysql_dump(%d): ",getpid()); s; 
//#define DEBUG(s)

void cipa(unsigned int ip, unsigned char cip[]);

//-----------------------------------------------------------------------------------
int main (int argc, char *argv[]) {
  t_config * config = (t_config *) malloc(sizeof(t_config));
  t_cat * cat = 0;                                                                      
  int i,fifo,timetag,input,output;
  unsigned char cip[4];
  t_data data;
  extern int errno;
  MYSQL mysql;
  char query[QUERYLENGTH];
  pid_t ppid;

  openlog("traff_mysql_dump",LOG_PID,LOG_DAEMON);
  syslog(LOG_INFO, "Starting traff_mysql_dump");
  //fprintf(stderr,"Fifo Filename: %s Category %s\n", argv[1],argv[2]);
//  if (argc != 3) exit(1);
  
//  config_init(config,argv[3]); 
 
  ppid = atoi( argv[4] );
  DEBUG(printf("Parrent is %d\n",ppid);)
  DEBUG(printf("Debuging Mode Enabled\n");)
  DEBUG(printf("Openning Configugariotn file %s...\n", argv[3]);)
  config_init(config,argv[3]); 
  
  cat = config->cats;
  while(strcmp(cat->name,argv[2])) 
    cat = cat->next;
  if (!cat)
    fprintf(stderr,"Did not fount Cat %s ind file %s\n",argv[2],argv[3]);
  
  mysql_init(&mysql);
  mysql_connect(&mysql,cat->sql->host,cat->sql->user,cat->sql->password);
  if (mysql_errno(&mysql)) {
    printf("Error connecting to Mysql-Database:\n%d, %s\n", mysql_errno(&mysql),mysql_error(&mysql));
    syslog(LOG_ERR,"Error connecting to Mysql-Database:\n%d, %s\n", mysql_errno(&mysql),mysql_error(&mysql));
    kill(ppid, SIGKILL);
    unlink(argv[1]);
    exit(1);
  }
  mysql_select_db(&mysql,cat->sql->db); 
  if (mysql_errno(&mysql)) {
    printf("Error connecting to Mysql-Database:\n%d, %s\n", mysql_errno(&mysql),mysql_error(&mysql));
    syslog(LOG_ERR,"Error connecting to Mysql-Database:\n%d, %s\n", mysql_errno(&mysql),mysql_error(&mysql));
    kill(ppid, SIGTERM);
    unlink(argv[1]);
    exit(1);
  }

  if ( (fifo = open(argv[1],O_RDONLY)) == -1 ) {
    fprintf(stderr, "%s: Cat: %s: Error opening fifo %s for reading.\nError: %s\n",argv[0],argv[2],argv[1],strerror(errno));
    syslog(LOG_ERR, "%s: Cat: %s: Error opening fifo %s for reading.\nError: %s\n",argv[0],argv[2],argv[1],strerror(errno));
    kill(ppid, SIGTERM);
    unlink(argv[1]);
    exit(1);
  }

  if (cat->timedivider) timetag = (int) time(0) / cat->timedivider;
  else timetag = time(0);
  
  while(read(fifo, &data, sizeof(t_data))) {
    input = (int) data.input / cat->bytedivider;
    output = (int) data.output / cat->bytedivider;
    if (input || output) {
      cipa(data.ip, cip);
      snprintf(query,QUERYLENGTH,"update %s set input=input+%d,output=output+%d where ip=\"%d.%d.%d.%d\" and timetag=%d",cat->sql->table,input,output,cip[0],cip[1],cip[2],cip[3],timetag);
      DEBUG(printf("Query: %s\n", query);)
    
      if (mysql_query(&mysql,query)){
        printf("Error connecting to Mysql-Database:\n%d, %s\n", mysql_errno(&mysql),mysql_error(&mysql));
        syslog(LOG_ERR,"Error connecting to Mysql-Database:\n%d, %s\n", mysql_errno(&mysql),mysql_error(&mysql));
        kill(ppid, SIGTERM);
        unlink(argv[1]);
        exit(1);
      }
      DEBUG(printf("Error: %s, Affected Rows: %d\n",mysql_error(&mysql), mysql.affected_rows );)  
      if (! mysql.affected_rows) {
      	snprintf(query,QUERYLENGTH,"insert into %s (ip,timetag,input,output) values (\"%d.%d.%d.%d\",%d,%d,%d)",cat->sql->table,cip[0],cip[1],cip[2],cip[3],timetag,input,output);
        DEBUG(printf("First entry: using query:  %s\n",query);)
	      mysql_query(&mysql,query);
        DEBUG(printf("%s\n",mysql_error(&mysql));)  
      
      }

    }
  }
  
  mysql_close(&mysql);
  close(fifo);
  sleep(2);
  unlink(argv[1]);
} // main
//-----------------------------------------------------------------------------------
void cipa(unsigned int ip, unsigned char cip[]) {
  cip[0] = ip>>24;
  cip[1] = ((ip<<8)>>24);
  cip[2] = ((ip<<16)>>24);
  cip[3] = ((ip<<24)>>24);
}
