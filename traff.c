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

//#define DEBUG(s) printf("traff(%d): ",getpid()); s
#define DEBUG(s)


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
typedef struct pcap_pkthdr t_pcap_pkthdr;

void print_config( t_config * config);
void cipa(unsigned int ip, unsigned char cip[]);
void catch_signal(int sig);
void account(t_account * account_inf);
void dump(t_cat * cat);
void read_device(t_interface_list * device);
void push_queue(t_interface_list * device, const struct pcap_pkthdr *h, const u_char *raw_pkt); 
int pop_queue(t_interface_list * device, t_raw_data * dst_data);
void init_queue(t_interface_list * device);
void delete_queue(t_interface_list * device);
void start_accounting(t_config * config);
void process_packages (t_config * config);
void print_data(t_raw_data * data);

// Global Variables
int cycle = 1;    // Our programm will runn as long as this variable is set.
int info = 0;     // If this is set some information will be dumped to stderr
int dumping = 0;  // This holds the number od thrteads that are dumping information.
int dt = 0;       // dt stores the last time a dump was done. It must be global so a dump can be triggered by a signal


//-----------------------------------------------------------------------------------
int main (int argc, char *argv[]) {
  t_config * config = (t_config *) malloc(sizeof(t_config));
  int i,child;
  t_interface_list * devices,temp1_dev,temp2_dev ;                
  
  signal(SIGCHLD, SIG_IGN);

  // reading config file
  config_init(config,"/etc/traff.conf"); // this function will initialize configuration
  config->dt = time(0);
  // inititlizing Pcap
  devices = config->devices;
  DEBUG(printf("Starting FORK-sequence...\n");)
  for (i = 0; i < config->devicecount; i++)  {
    DEBUG(printf("Forking for the %d. time: Device: %s\n",i,devices->name);)
    child = fork();
    if (child == 0) {
      //this is the child
      //Reduce the config->devices to only the one we are using:
//      temp1_dev = config->devices;
//      while (temp1_dev) {
//        if (temp1_dev != devices) {
//          temp2_dev = temp1_dev;
//          temp1_dev = temp1_dev->next;
//          free(temp2_dev);
//        }  
//      }
      config->devices = devices;
      config->devices->next = 0;
      // done reducing devices.
      
      start_accounting(config);
      exit(0);
    } else if (child > 0) {
      // I am Parrent
      DEBUG(printf("Lauched Child with PID %d\n",child);)
      config->dt += 20; // Create a offset, so dump-programms do not execute all at the same time  
      devices = devices->next; // Get next device for next fork
    } else {
      printf("Error while forking\n");
      exit(1);
    }
  }
  exit(0);
} // main
//-----------------------------------------------------------------------------------
void start_accounting(t_config * config) {
  // this function dooes the main part. It is executed once for each device.
  pthread_attr_t  pthread_attr_detach;
  t_cat * cat = 0;                                                                      
  char buff[PCAP_ERRBUF_SIZE];
  unsigned char *raw_pkt;
  struct pcap_pkthdr pkthdr;
  t_account account_inf;
  pthread_t thread;
  int dt;
  t_interface_list * device;                
  
  pthread_attr_init(&pthread_attr_detach);
  pthread_attr_setdetachstate(&pthread_attr_detach, PTHREAD_CREATE_DETACHED);
  dt = config->dt;
  device = config->devices;
 
  // First: initialize everything
  signal(SIGUSR1, catch_signal);
  signal(SIGUSR2, catch_signal);
  signal(SIGHUP,  catch_signal);
  signal(SIGTERM, catch_signal);
  signal(SIGCHLD, SIG_IGN);

  DEBUG(printf("Opening Device %s\n",device->name);)
  device->device = pcap_open_live(device->name, 96, 1,100, buff);
  if (! device->device) { 
    printf("Error opening device %s\n",device->name);
    exit(1); 
  }
  //initializing device-queue
  init_queue(device);
  
  //initializing Categories
  while (cat) {                                                                                    
    data_init(cat);      
    cat = cat->next;
  }
 
  //------------ Initialization Done ---------------
  while (cycle) {
    //fill package buffer...
    nice(-5);
    DEBUG(printf("Calling loop on device %s for %d packages\n",device->name, device->package_count);) 
    pcap_loop(device->device, device->package_count, (pcap_handler) push_queue, (u_char *) device);  
    
    // Call the thread to account data and empty buffer
    pthread_create(&thread, &pthread_attr_detach, (void*) process_packages, (void*) config);
    
  
  } // while (cycle || dt)

  // ------------ Clean-up Funktions here -----------------
 

} // start_accountin 

//-----------------------------------------------------------------------------------
void process_packages (t_config * config) {
  t_raw_data data;
  t_cat * cat = 0;                                                                      
  t_cat * thread_cat = 0;                                                                      
  pthread_attr_t  pthread_attr_detach;
  pthread_t thread;

  
  pthread_attr_init(&pthread_attr_detach);
  pthread_attr_setdetachstate(&pthread_attr_detach, PTHREAD_CREATE_DETACHED);
  // first add all packtes in buffer to the table:
  while (pop_queue(config->devices,&data)) {
    DEBUG(printf("Accounting package:\n"); print_data(&data); )
      
    // now that we have the package we should pass it to each category, so it can be processed 
    cat = config->cats;                                                                      
    while(cat) {
      data_account(cat, &data);
      cat = cat->next;
    }
    
  } // did accounting for packages in queue

  // now do the dumpinmg if time elapsed...
  if ((config->dt + config->cycletime < time(0)) || ! cycle ) { 
    config->dt = time(0);
    if (! cycle) config->dt = 0; // when cycle is set to 0 we will make a dump and no longer cycle

    if (dumping) {
      printf("Trying to dump while other dump is active. Ignoring this dump");
    } else {
      cat = config->cats;                                                                      
      while (cat) {                                                                                    
        thread_cat = malloc(sizeof(t_cat));
        memcpy(thread_cat, cat,sizeof(t_cat));
        data_init(cat);      
        signal(SIGCHLD, SIG_IGN);
        pthread_create(&thread, &pthread_attr_detach, (void*)&dump, (void*) thread_cat);
        // now associate a new table to the category. The thread will be responseble for 
        // destroying the old one
        cat = cat->next;
      } //while (cat) 
    }   //if (dumping)
  } //if ((dt + config->cycletime < time(0)) || ! cycle )
  

} // process_packages
//-----------------------------------------------------------------------------------
void read_device(t_interface_list * device) {
  nice(-5);
  pcap_loop(device->device, -1, (pcap_handler) push_queue, (u_char *) device);  
  exit(0);  
}
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
    printf("| Device: %s Buffer: %d%\n",devices->name, (int)(devices->write_buffer - devices->read_buffer)/BUFFERSIZE );
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
void print_data(t_raw_data * data) {
  unsigned char ip1[4];
  unsigned char ip2[4];
  cipa(data->ip[0],ip1);
  cipa(data->ip[1],ip2);
  
  printf("%3d.%3d.%3d.%3d:%5d %3d.%3d.%3d.%3d:%5d %3d %d\n",
         ip1[0],ip1[1],ip1[2],ip1[3],data->port[0],
         ip2[0],ip2[1],ip2[2],ip2[3],data->port[1],
         data->prot, data->length);
}
//-----------------------------------------------------------------------------------
void cipa(unsigned int ip, unsigned char cip[]) {
  cip[0] = ip>>24;
  cip[1] = ((ip<<8)>>24);
  cip[2] = ((ip<<16)>>24);
  cip[3] = ((ip<<24)>>24);
}
//-----------------------------------------------------------------------------------
void init_queue(t_interface_list * device) {
  int i;
  device->buffer = malloc(sizeof(t_BUFFER));
  device->read_buffer = 0;
  device->write_buffer = 0;
  DEBUG(printf("Initializing Queue for device %s with %d entries\n",device->name,BUFFERSIZE);)
  for(i = 0;i < BUFFERSIZE; i++) {
    (*device->buffer)[i] = malloc(sizeof(t_raw_data));
  }
}
//-----------------------------------------------------------------------------------
void delete_queue(t_interface_list * device) {
  int i;
  device->read_buffer = -1;
  device->write_buffer = -1;
  DEBUG(printf("Deleting queue for device %s\n",device->name);)
  for(i = 0;i < BUFFERSIZE; i++) {
    free( (* device->buffer)[i] );
    (*device->buffer)[i] = 0; 
  }
  free(device->buffer);
}
//-----------------------------------------------------------------------------------
void push_queue(t_interface_list * device, const struct pcap_pkthdr *h, const u_char *raw_pkt) {
  t_raw_data * data;
  eth_struct_t *eth_pkt = 0;
  ip_struct_t  *ip_pkt  = 0;

  DEBUG(printf("Inserting package into queue of device %s: wb:%d rb:%d\n",device->name,device->write_buffer,device->read_buffer);)
  // Point data to where dta should be stored
  data = (t_raw_data *) (*device->buffer)[device->write_buffer];

  if (raw_pkt !=NULL) { // if we recieve a empty package continue
    eth_pkt = (eth_struct_t *) raw_pkt;
    if (eth_pkt->ptype[0]==8 && eth_pkt->ptype[1] == 0) {
      // The package is a ip
      ip_pkt = (ip_struct_t *) (raw_pkt + 14);                                                    
      //Converts Data:
      DEBUG(printf("IP-Package %d.%d.%d.%d:%5d -> %d.%d.%d.%d:%5d\n",
            ip_pkt->srcip[0],ip_pkt->srcip[1],ip_pkt->srcip[2],ip_pkt->srcip[3],((ip_pkt->srcpt[0] << 8) + ip_pkt->srcpt[1]),
            ip_pkt->dstip[0],ip_pkt->dstip[1],ip_pkt->dstip[2],ip_pkt->dstip[3],((ip_pkt->dstpt[0] << 8) + ip_pkt->dstpt[1]));)

      data->ip[0]  = ((ip_pkt->srcip[0] << 24) + (ip_pkt->srcip[1] << 16) + (ip_pkt->srcip[2] << 8) + ip_pkt->srcip[3]);
      data->ip[1]  = ((ip_pkt->dstip[0] << 24) + (ip_pkt->dstip[1] << 16) + (ip_pkt->dstip[2] << 8) + ip_pkt->dstip[3]);
      data->port[0]  = ((ip_pkt->srcpt[0] << 8) + ip_pkt->srcpt[1]);
      data->port[1]  = ((ip_pkt->dstpt[0] << 8) + ip_pkt->dstpt[1]);
      data->length = (ip_pkt->length[0] *256 + ip_pkt->length[1]);
      data->prot  = ip_pkt->prot[0];
      // Increment Write_buffer.
      DEBUG(printf("Inserting package: "); print_data(data); )
      device->write_buffer = (device->write_buffer + 1) % BUFFERSIZE;
    }
  }
}
//-----------------------------------------------------------------------------------
int pop_queue(t_interface_list * device, t_raw_data * dst_data) {
  t_raw_data * data;
  // Point data to source of data
  data = (t_raw_data *) (*device->buffer)[device->read_buffer];
  
  if (device->read_buffer == device->write_buffer) {
    //DEBUG(printf("Popping package: No package for device %s\n",device->name);)
    return 0;
  } else {
    DEBUG(printf("Popping package from queue of device %s\n",device->name);)
    memcpy(dst_data,data,sizeof(t_raw_data));
    //increment read_buffer for next read
    device->read_buffer = (device->read_buffer + 1) % BUFFERSIZE;
    return 1;
  }
}
//-----------------------------------------------------------------------------------
// old
    //    raw_pkt =  (unsigned char *) pcap_next(devices->device,&pkthdr);// reading package :)
//    if (raw_pkt==NULL) continue; // if we recieve a empty package continue
                   
//    eth_pkt = (eth_struct_t *) raw_pkt;
//    if (eth_pkt->ptype[0]==8 && eth_pkt->ptype[1]==0) {
      // The package is a ip
//      ip_pkt = (ip_struct_t *) (raw_pkt + 14);                                                    

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
  
      
