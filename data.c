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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
//#include <pcap.h>
#include <signal.h>
//#include <limits.h>
//#include <unistd.h>
#include <fcntl.h>
//#include <time.h>
//#include <netinet/in.h>
#include "readconfig.h"
#include "data.h"
//#include "ip_table.h"

//------------------------------------------------------------------------------------
void data_dump(t_cat *cat){
  extern int errno;
  extern char conf_file[];
  char * fifo_file;
  t_data * data = 0;
  int fifo;
  pid_t child,parrent;
 
  fifo_file = tempnam(0,"traff");
  parrent = getpid(); 
  mkfifo(fifo_file,0600);
  
  //fprintf(stderr, "Going to fork\n");
  child = fork();
   
  if (child == 0) {
    if (execlp(cat->dump_programm,cat->dump_programm,fifo_file, cat->name,conf_file,parrent,0) != 0 ) fprintf(stderr, "Error executing programm %s\nError: %s\n",cat->dump_programm,strerror(errno));
    pthread_exit(0);
  } else if (child < 0) {
     fprintf(stderr, "Traff Dump Cat: %s: Error while forking at datadump\n",cat->name);
     pthread_exit(0);
  }

  if ( (fifo = open(fifo_file,O_WRONLY)) == -1  ) {
    fprintf(stderr, "Traff Dump Cat: %s: Error opening fifo %s for writing.\nError: %s",cat->name,fifo_file, strerror(errno));
    kill(child, SIGTERM);
    pthread_exit(0);      
  }

  data = (t_data *) ip_table_fetch_next(cat->table,0);
  while (data) {
    if(write(fifo, data, sizeof(t_data)) != sizeof(t_data)) {
      fprintf(stderr, "Traff Dump Cat: %s: Error dumping data.\n",cat->name);
    }
    if (data->ip != 0xffffffff) {
      data = (t_data *) ip_table_fetch_next(cat->table,data->ip+1);
    } else data = 0;
  }

  close(fifo);
  //fprintf(stderr, "Going to destroy table\n");  
  data_destroy_table(cat->table);
  free(cat);
}
//------------------------------------------------------------------------------------
void data_destroy_table(void* table) {
  // This function will clean up. It will release the memory allocated by data, ask 
  // ip_table to destroy the table. 

  t_data * data = 0;
  unsigned int ip = 0;
  unsigned char cip[4];                                                                            

  //fprintf(stderr, "data_destroy_table: FEtching first entry\n");  
  //fprintf(stderr, "entries in table: %d\n",ip_table_count(table));
  data = (t_data *) ip_table_fetch_next(table,0);
  while (data) {
    //lets cycle throught the table...
    ip = (data->ip);
    free((t_data *)data); // and free everu entry
    ip_table_insert(table,ip,0); // Set the pointer to this entry to 0;
    if (ip != 0xffffffff) {
      ip++;      
      data = (t_data *) ip_table_fetch_next(table,ip);
    } else data = 0;
  }
  // noe we can ask ip_table to free the rest
  //fprintf(stderr, "data_destroy_table: passing over to ip_table_destroy_table\n");  
  ip_table_destroy_table(table,0);
}
//------------------------------------------------------------------------------------
int data_match_rule(t_ip_filter *filter,  t_raw_data * data, int i) {
  t_ip_filter *tempfilter = filter;

  // cycle throught all filters, by return on fiorst match
  while (filter) {
    //printf("Matching IP: !((%8x & %8x) ^ %8x) = %8x ",data->ip[i],filter->mask, filter->ip,!((data->ip[i] & filter->mask) ^ filter->ip));
    //printf("PORT: (%2d == %2d) = %2d\n",data->port[i],filter->port,(data->port[i] == filter->port));
    if ( !((data->ip[i] & filter->mask) ^ filter->ip) &&
         !(( filter->port) &&  (data->port[i] ^ filter->port))
       ) {
           // Filter port is set to 0 or port matches
//         ((! filter->prot)|| (data->prot == filter->prot)  ) ) { // Protocol is set to 0 or matches
      return filter->value;
    }
    filter = filter->next;
  }
      

  //By default we will return 0. This means, that if no Rules are specified
  //nothing will be accounted
  return 0; 
}
//-------------------------------------------------------------------------------------
void data_account(t_cat *cat, t_raw_data * data) {
  int i;
  char cip[4];
  t_data * temp_pkt = 0;
  
  // check the package
  // But we have to check in both direction. Once Src-IP being primary an once Dst-IP beeing primary
  for(i=0; i < 2; i++ ){
    if(! data_match_rule(cat->primary, data, i)) continue;
    if(! data_match_rule(cat->secondary, data, 1-i)) continue;

    temp_pkt = (t_data *)ip_table_get_entry(cat->table,(*data).ip[i]);
    if (! temp_pkt) {
      // No entry, creating one
      temp_pkt = malloc(sizeof(t_data));
      memset(temp_pkt,0,sizeof(t_data));
      temp_pkt->ip = (*data).ip[i];
      ip_table_insert(cat->table,(*data).ip[i], (void*)temp_pkt);
    }

    // Now add information
    if (i==0) {
      temp_pkt->output += data->length;
    } else {
      temp_pkt->input += data->length;
    }

  
  }

}
//-------------------------------------------------------------------------------------
void data_init(t_cat *cat) {
  cat->table = (void *) ip_table_init();
}
//-------------------------------------------------------------------------------------
void data_print_info(t_cat *cat) {
  t_data * data = 0;
  unsigned int ip = 0;
  unsigned char cip[4];                                                                            
   
  printf("Detailed information on %s\n", cat->name);
  printf("Number of entries in Table: %d\n", ip_table_count(cat->table));

  data = (t_data *) ip_table_fetch_next(cat->table,0);
  while (data) {
    ip = (data->ip);
    data_cipa(ip,cip);
    printf("IP: %03d.%03d.%03d.%03d  input: %8d output %8d\n", cip[0],cip[1],cip[2],cip[3], data->input, data->output);
    
    if (ip != 0xffffffff) {
      ip++;      
      data = (t_data *) ip_table_fetch_next(cat->table,ip);
    } else data = 0;
  }
  
        
}
//-------------------------------------------------------------------------------------
void data_cipa(unsigned int ip, unsigned char cip[]) {
  cip[0] = ip>>24;
  cip[1] = ((ip<<8)>>24);
  cip[2] = ((ip<<16)>>24);
  cip[3] = ((ip<<24)>>24);
}
