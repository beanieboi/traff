
#ifndef READCONFIG_H
#define READCONFIG_H

#define TEXTLEN 8 
#define FILELENGTH 30
#define DEBUG

#include <pcap.h> 
#include <pthread.h> 
//#include "ip_table.h"

typedef unsigned int U_INT;
typedef unsigned char U_CHAR;

typedef struct t_ip_filter {
  U_INT ip;
  U_INT mask;
  U_INT port;
  U_CHAR prot;
  int value;
  struct t_ip_filter * next;
} t_ip_filter;

typedef struct t_interface_list {
  pcap_t * device;
  char name[TEXTLEN];
  struct t_interface_list * next;
} t_interface_list;

typedef struct t_cat {
  char name[TEXTLEN];
  t_ip_filter *primary;
  t_ip_filter *secondary;
  void * table;
  U_INT table_next;
  int timedivider;
  int bytedivider;
  pthread_t thread;
  struct t_cat *next;
  char dump_programm[FILELENGTH];
} t_cat;

typedef struct t_config {
  int cycletime;
  int devicecount;
  t_interface_list * devices;
  t_cat * cats;
} t_config;

typedef struct {
  U_INT ip[2];
  U_INT port[2];
  U_INT length;
  U_CHAR prot;
} t_raw_data;

typedef struct t_data {
  U_INT ip;
  U_INT input;
  U_INT output;
} t_data;      


void config_init(t_config * config,char * filename);
void test_init(t_config * config);



#endif
