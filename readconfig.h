#include "config.h"

#ifndef READCONFIG_H
#define READCONFIG_H

#define TEXTLEN 32
#define FILELENGTH 1024
#define LONGTEXT 32
#define QUERYLENGTH 1024

#if WITH_MYSQL
#include <mysql.h>
#endif

#if WITH_PSQL
#include <libpq-fe.h>
#endif

#include <errno.h>
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
// #include "ip_table.h"

typedef unsigned int U_INT;
typedef unsigned char U_CHAR;

typedef enum {
  dt_Stdout,
  dt_Syslog,
  dt_Textfile,
  dt_Binfile,
  dt_Mysql,
  dt_Pgsql,
  dt_BadOption
} e_dumptypes;

static struct {
  const char *name;
  e_dumptypes dump_type;
} dump_types[] = {{"StdOut", dt_Stdout},
                  {"Syslog", dt_Syslog},
                  {"TextFile", dt_Textfile},
                  {"BinFile", dt_Binfile},
                  {"MySQL", dt_Mysql},
                  {"PgSQL", dt_Pgsql},
                  {"--Error: Bad Option--", dt_BadOption},
                  {NULL, 0}};

typedef struct t_ip_filter {
  U_INT ip;
  U_INT mask;
  U_INT port;
  U_CHAR prot;
  int value;
  struct t_ip_filter *next;
} t_ip_filter;

#define BUFFERSIZE 10000
typedef void *t_BUFFER[BUFFERSIZE];
typedef struct t_interface_list {
  pcap_t *device;
  pthread_t *thread;
  // not needed any more (KD)
  int package_count;
  int buffersize;
  int write_buffer;
  char name[TEXTLEN];
  struct t_interface_list *next;
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
  void *table;
  U_INT table_next;
  int timedivider;
  int bytedivider;
  pthread_t thread;
  struct t_cat *next;
  e_dumptypes dump_type;
  t_sql *sql;
  char *filename;
} t_cat;

typedef struct t_config {
  int cycletime;
  int devicecount;
  int dt;
  int buffer_size;
  t_interface_list *devices;
  t_cat *cats;
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

t_config *config_init(t_config *config, char *filename);
int config_read_config_file(t_config *config, char *filename);
void config_destroy(t_config *config);
char *get_dump_type_str(e_dumptypes dumptype);

char conf_file[FILELENGTH];

#endif
