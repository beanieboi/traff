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
#include <pcap.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>
#include <pthread.h>                                                                               
#include "readconfig.h"

#define CAT_THREAD 0  //If this is set, threats will be created to account data
#define DUMP 2   //0 will do nothing, 1 will use threads 2 will use fork

//typedef unsigned char U_CHAR;
typedef struct {
  U_CHAR version[1];
  U_CHAR service[1];
  U_CHAR length[2];
  U_CHAR id[2];
  U_CHAR flag[2];
  U_CHAR ttl[1];
  U_CHAR prot[1];
  U_CHAR chksum[2];
  U_CHAR srcip[4];
  U_CHAR dstip[4];
  U_CHAR srcpt[2];
  U_CHAR dstpt[2];
} ip_struct_t;
typedef struct {
  U_CHAR src[6];
  U_CHAR dst[6];
  U_CHAR ptype[2];     /*  ==0x800 if ip  */
} eth_struct_t;
typedef struct {
  t_cat * cat;                                                                      
  t_raw_data * data;  
} t_account;

void print_config( t_config * config);
void cipa(unsigned int ip, unsigned char cip[]);
void catch_signal(int sig);
void account(t_account * account_inf);
void dump(t_cat * cat);

// Global Variables
int cycle = 1;    // Our programm will runn as long as this variable is set.
int info = 0;     // If this is set some information will be dumped to stderr
int dumping = 0;  // This holds the number od thrteads that are dumping information.
int dt = 0;       // dt stores the last time a dump was done. It must be global so a dump can be triggered by a signal

//-----------------------------------------------------------------------------------
int main (int argc, char *argv[]) {
  t_config * config = (t_config *) malloc(sizeof(t_config));
  t_cat * cat = 0;                                                                      
  t_cat * thread_cat = 0;                                                                      
  pthread_attr_t  pthread_attr_default;
  pthread_attr_t  pthread_attr_detach;

  
  // Things neede by pcap
  char buff[PCAP_ERRBUF_SIZE];
  unsigned char *raw_pkt;
  struct pcap_pkthdr pkthdr;
  int i;
  eth_struct_t *eth_pkt = 0;
  ip_struct_t  *ip_pkt  = 0;
  t_interface_list * devices = 0;                
  t_raw_data data;
  t_account account_inf;

  pthread_t thread;
  
  // First: initialize everything
  signal(SIGUSR1, catch_signal);
  signal(SIGUSR2, catch_signal);
  signal(SIGHUP,  catch_signal);
  signal(SIGTERM, catch_signal);
  signal(SIGCHLD, SIG_IGN);

  pthread_attr_init(&pthread_attr_default);
  pthread_attr_init(&pthread_attr_detach);
  pthread_attr_setdetachstate(&pthread_attr_detach, PTHREAD_CREATE_DETACHED);
  dt = time(0);
  // reading config file
  config_init(config,"/tmp/traff.conf"); // this function will initialize configuration
  // inititlizing Pcap
  devices = config->devices;
  for (i = 0; i < config->devicecount; i++)  {
    devices->device = pcap_open_live(devices->name, 96, 1,1000, buff);
    if (! devices->device) { 
      printf("Error opening device %s\n",devices->name);
      exit(1); 
    }
    devices = devices->next;
  }
  // initializing Categories: Let data_init do the rest config_init could not do
  cat = config->cats;                                                                      
  while (cat) {                                                                                    
    data_init(cat);      
    cat = cat->next;
  }


  // now we can start accounting
  devices = config->devices;
  while (cycle || dt) {
    raw_pkt =  (unsigned char *) pcap_next(devices->device,&pkthdr);// reading package :)

    if (raw_pkt==NULL) continue; // if we recieve a empty package continue
                   
    eth_pkt = (eth_struct_t *) raw_pkt;
    if (eth_pkt->ptype[0]==8 && eth_pkt->ptype[1]==0) {
      // The package is a ip
      ip_pkt = (ip_struct_t *) (raw_pkt + 14);                                                    

      #if 0 
      printf ("%03d.%03d.%03d.%03d %03d.%03d.%03d.%03d  %3d %5d %5d %5d\n",
           ip_pkt->srcip[0],ip_pkt->srcip[1],ip_pkt->srcip[2],ip_pkt->srcip[3],
           ip_pkt->dstip[0],ip_pkt->dstip[1],ip_pkt->dstip[2],ip_pkt->dstip[3],
           ip_pkt->prot[0],
           ip_pkt->srcpt[0]*256+ip_pkt->srcpt[1],
           ip_pkt->dstpt[0]*256+ip_pkt->dstpt[1],
           ip_pkt->length[0]*256+ip_pkt->length[1]);
      #endif
    
      //setting values in data to be passed later on
      data.ip[0]  = ((ip_pkt->srcip[0] << 24) + (ip_pkt->srcip[1] << 16) + (ip_pkt->srcip[2] << 8) + ip_pkt->srcip[3]);
      data.ip[1]  = ((ip_pkt->dstip[0] << 24) + (ip_pkt->dstip[1] << 16) + (ip_pkt->dstip[2] << 8) + ip_pkt->dstip[3]);
      data.length = (ip_pkt->length[0] *256 + ip_pkt->length[1]);
      data.prot  = ip_pkt->prot[0];
  
      
      // now that we have the package we should pass it to each category, so it can be processed 
      cat = config->cats;                                                                      
      while(cat) {

        #if CAT_THREAD
        account_inf.cat = cat; 
        account_inf.data = &data;
        //creating thread
        pthread_create( &cat->thread, &pthread_attr_default, (void*)&account, (void*) &account_inf);
        #else
        data_account(cat, &data);
        #endif
        cat = cat->next;
      }

      #if CAT_THREAD
      cat = config->cats;                                                                      
      while(cat) {
        pthread_join( cat->thread,0);
        cat->thread = 0;
        cat = cat->next;
      }
      #endif

      
    } // if Pakage is of type IP
            
    // now lets pint DEvices to the next device, so all devices are read. 
    // REmember that devices is a RING-List: The last element points to the first. If Only
    // one element exists it will point to itselv.

    // This prints some information on the screen.
    if (info) {
      print_config(config);
      cat = config->cats;
      while(cat) {
        data_print_info(cat);
        cat = cat->next;
      }
      info = 0;
    }
    
    // check if we should dump informatoion again
    if ((dt + config->cycletime < time(0)) || ! cycle ) { 
      dt = time(0);
      if (! cycle) dt = 0; // when cycle is set to 0 we will make a dump and no longer cycle

      if (dumping) {
        printf("Trying to dump while other dump is active");
        exit(0);
      }

      cat = config->cats;                                                                      
      while (cat) {                                                                                    
        thread_cat = malloc(sizeof(t_cat));
        memcpy(thread_cat, cat,sizeof(t_cat));
        //thread_cat->table = cat->table;
        data_init(cat);      
        //fprintf(stderr, "Old table: %x, new table %x\n",thread_cat->table,cat->table);
        pthread_create(&thread, &pthread_attr_detach, (void*)&dump, (void*) thread_cat);
//        pthread_detach(thread);
        // now associate a new table to the category. The thread will be responseble for 
        // destroying the old one
        cat = cat->next;
      }
    } 

    devices = devices->next;

  } // while (cycle)

  // Cleaning up
  devices = config->devices;
  for (i = 0; i < config->devicecount; i++)  {
    pcap_close(devices->device);
    devices->device = 0;
    devices = devices->next;
  }
  
  free(config);
  config = 0;
 
  pthread_exit(0);
  
} // main
//-----------------------------------------------------------------------------------
void dump(t_cat * cat) {
  //fprintf(stderr, "dump: Staring dump\n");
  dumping++;
  data_dump(cat);
  dumping--;
  //fprintf(stderr, "dump: Dump done\n");
  pthread_exit(0);
}
//-----------------------------------------------------------------------------------
void account(t_account * account_inf) {
  //this function does nothing else then converting account_inf and executing data_account
  //it is only used if threads are enabled
  data_account((t_cat *)account_inf->cat, (t_raw_data *)account_inf->data);
  pthread_exit(0);
}
//-----------------------------------------------------------------------------------
void catch_signal(int sig) {
  if (sig == SIGUSR1) info = 1;
  else if (sig == SIGUSR2) dt = 1;
  else cycle = 0;
}
//-----------------------------------------------------------------------------------
void print_config( t_config * config) {
  t_interface_list * devices = config->devices;
  t_cat * cat = config->cats;
  t_ip_filter * filter = 0;
  unsigned char cip[4];
  int i;
  
  printf("Cycletime: %d\n", config->cycletime);
  printf("Devicecount: %d\n",config->devicecount);
  printf("Devices:\n"); 

  for (i = 0; i < config->devicecount; i++)  {
    printf("| %s\n",devices->name);
    devices = devices->next;
  }

  while (cat) {
    printf("Cat: %s\n",cat->name);
    printf(" Byte Divider: %d\n",cat->bytedivider);
    printf(" Time Divider: %d\n",cat->timedivider);
    
    filter = cat->primary;  
    printf(" Primary:\n");
    while (filter) {
      cipa(filter->ip,cip);      
      printf(" | IP: %03d.%03d.%03d.%03d ", cip[0], cip[1], cip[2], cip[3]);
      cipa(filter->mask,cip); 
      printf("MASK: %03d.%03d.%03d.%03d VALUE: %1d PORT: %5d PROT: %3d\n", cip[0], cip[1], cip[2], cip[3],filter->value,filter->port,filter->prot);
      filter = filter->next;
    }
    printf(" | IP: 000.000.000.000 MASK: 000.000.000.000 VALUE: 0\n");
    
    
    filter = cat->secondary;  
    printf(" Secondary:\n");
    while (filter) {
      cipa(filter->ip,cip);      
      printf(" | IP: %03d.%03d.%03d.%03d ", cip[0], cip[1], cip[2], cip[3]);
      cipa(filter->mask,cip); 
      printf("MASK: %03d.%03d.%03d.%03d VALUE: %1d PORT: %5d PROT: %3d\n", cip[0], cip[1], cip[2], cip[3],filter->value,filter->port,filter->prot);
      filter = filter->next;
    }
    printf(" | IP: 000.000.000.000 MASK: 000.000.000.000 VALUE: 0\n");
    
    cat = cat->next;
  } // while (cat)
}
//-----------------------------------------------------------------------------------

void cipa(unsigned int ip, unsigned char cip[]) {
  cip[0] = ip>>24;
  cip[1] = ((ip<<8)>>24);
  cip[2] = ((ip<<16)>>24);
  cip[3] = ((ip<<24)>>24);
}


