
#ifndef READCONFIG_H
#define READCONFIG_H

#define TEXTLEN 32 
#define FILELENGTH 1024
#define LONGTEXT 32
//#define DEBUG

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


#define BUFFERSIZE 500
typedef void* t_BUFFER[BUFFERSIZE];
typedef struct t_interface_list {
  pcap_t * device;
  t_BUFFER *  buffer;
  int read_buffer;
  int package_count;
  int buffersize;
  int write_buffer;
  char name[TEXTLEN];
  struct t_interface_list * next;
} t_interface_list;

typedef struct t_sql {
  char host[LONGTEXT];
  char db[LONGTEXT];
  char table[LONGTEXT];
  char user[LONGTEXT];
  char password[LONGTEXT];
} t_sql;

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
  t_sql * sql;
} t_cat;

typedef struct t_config {
  int cycletime;
  int devicecount;
  int dt;
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


t_config * config_init(t_config * config,char * filename);
int config_read_config_file(t_config * config,char * filename);
void config_destroy(t_config * config);

char conf_file[FILELENGTH];

#endif
