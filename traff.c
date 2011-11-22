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
#include <assert.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>
#include <pthread.h>                                                                               
#include <syslog.h>
#include "readconfig.h"
#include "ip_table.h"
#include "config.h"
#include <argp.h>

// added by KD
#include <semaphore.h>
#include <sys/time.h>


#define CAT_THREAD 0  //If this is set, threats will be created to account data
#define DUMP 2   //0 will do nothing, 1 will use threads 2 will use fork
#define DEBUG(s) {if ( arguments.debug ) {s}} while (0);

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

void print_config();
void push_queue(t_interface_list * device, const struct pcap_pkthdr *h, const u_char *raw_pkt); 
int pop_queue(t_raw_data * dst_data);
void init_queue(void);
void delete_queue(void);
void catch_signal(int signal);
void fill_queue(t_interface_list * device);

void data_account(t_cat *cat, t_raw_data * data);
int data_match_rule(t_ip_filter *filter,  t_raw_data * data, int i);
void data_print_info(t_cat *cat);
void data_destroy_table(void *table);
void data_dump(t_cat *cat);
void cipa(unsigned int ip, unsigned char cip[]);
void print_data(t_raw_data * data);
void data_init(t_cat *cat);
int data_mysql_dump (t_cat * cat);
int data_pgsql_dump (t_cat * cat);
int data_stdout_dump (t_cat * cat);
int data_syslog_dump (t_cat * cat);
int data_textfile_dump (t_cat * cat);
int data_binfile_dump (t_cat * cat);


// Global Variables
int cycle = 1;    // Our programm will run as long as this variable is set.
time_t last_dump;    // Stores the time when last dump was done;
int dumping = 0;
sem_t sem_dumping;

int queue_read_pointer = 0;
int queue_write_pointer = 0;
sem_t sem_queue_used, sem_queue_free;
t_raw_data * queue;
pthread_mutex_t lock_queue;
t_config *config;

const char *argp_program_version = 
PACKAGE_STRING "test";
const char *argp_program_bug_address =
"<mdormat@users.sourceforge.com>";

/* Program documentation. */
static char doc[] =
"Traff -- Traff sniffs you network interfaces and accounts the traffic on a IP basis. \
The configuration is very flexible allowing you to create different/multiple \
accounting rules. The collected data is stored using Mysql, PgSQL, Syslog or files.\
\v";

/* A description of the arguments we accept. */
static char args_doc[] = "";

/* The options we understand. */
static struct argp_option options[] = {
{"debug",  'd', 0,       0, "Produce debug output" },
{"config",  'c', "FILE",       0, "Configuration File default: /etc/traff.conf" },
{ 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments
{
int debug;   /* `-s', `-v', `--abort' */
char *config;
};

/* Parse a single option. */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
/* Get the input argument from argp_parse, which we
  know is a pointer to our arguments structure. */
struct arguments *arguments = state->input;

switch (key)
 {
 case 'd':
   arguments->debug = 1;
   break;
 case 'c':
   arguments->config = arg;
   break;
 default:
   return ARGP_ERR_UNKNOWN;
 }
return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc };
  struct arguments arguments;

//-----------------------------------------------------------------------------------
int main (int argc, char *argv[]) {
  //int i;
  //int * nic_listen_list;
  //int * child;
  t_cat * cat;
  t_cat * old_cat; 
  pthread_attr_t  pthread_attr_detach;
  pthread_t thread;
  t_interface_list * device;                
  t_raw_data packet;
    
  int i, j;
  
  /* Default values. */
  arguments.debug = 0;
  arguments.config = "/etc/traff.conf";
  
  /* Parse our arguments; every option seen by parse_opt will be
    reflected in arguments. */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);
  
  DEBUG(printf("Debugging Mode Enabled\n\n");)
  DEBUG(printf ("CONFIG_FILE = %s\nDEBUG = %s\n\n",arguments.config, arguments.debug ? "yes" : "no"); )

  last_dump = time(0);
  sem_init(&sem_dumping,0,1);

  openlog("traff",LOG_PID,LOG_DAEMON);
  syslog(LOG_NOTICE, "Starting traff Version %s",VERSION); 
  signal(SIGUSR1, catch_signal);
  signal(SIGHUP,  catch_signal);
  signal(SIGTERM, catch_signal);

  DEBUG(printf("Initializing Mutex\n");)
  if (pthread_mutex_init(&lock_queue, NULL)) {
    printf("Mutex init failed!\n");
    syslog(LOG_ERR, "Mutex init failed!");
    exit(1);  	
  }	

  DEBUG(printf("Reading Config\n");)
  config = (t_config *) malloc(sizeof(t_config));
  // reading config file
  config_init(config,arguments.config); // this function will initialize configuration
  config->dt = time(0);

  DEBUG(print_config();)

  init_queue();
    
  cat = config->cats;
  while (cat) {
    syslog(LOG_INFO, "Loading Category %s. Dump-Type: %s",cat->name,get_dump_type_str(cat->dump_type));
    cat = cat->next;
  }

  DEBUG(printf("Starting Thread sequence...\n");)
  pthread_attr_init(&pthread_attr_detach);
  pthread_attr_setdetachstate(&pthread_attr_detach, PTHREAD_CREATE_DETACHED);
  // Starting threads to listen to diferent devices  

  device = config->devices;
  while( device ) {
    syslog(LOG_INFO,"Listening on device %s.",device->name);
    DEBUG(printf("Forking for the %d. time: Device: %s\n",i,device->name);)
    // Starting functions to fill queue
    pthread_create(device->thread, &pthread_attr_detach, (void*) fill_queue, (void*) device);
    device = device->next;
  }

  // All initialization done
  while (cycle) {
    // create a new tree for each category
    DEBUG(printf("Initializing Cats\n");)
    cat = config->cats;
    while(cat) {
      DEBUG(printf("Initializing Category %s\n",cat->name);)
      data_init(cat);
      cat = cat->next;
    }

    while ((last_dump + config->cycletime > time(0)) && cycle) {
      // get packages from the queue
      pop_queue(&packet);

      // pass this packet to each category
      cat = config->cats;
      while(cat) {
        data_account(cat,&packet);
        cat = cat->next;
      }
    } // while (! dump)

    DEBUG(print_config();)

    last_dump = time(0);
    DEBUG(printf("starting dump-sequence\n");)
    if(dumping) {
      syslog(LOG_ERR,"ERROR: Privious dump still active. Aborting this one! Data lost! Please increase cycle time.");
    } else {
      cat = config->cats;
      while(cat) {
	syslog(LOG_INFO,"Dumping category %s",cat->name );
	DEBUG(printf("Dumping Category %s\n",cat->name);)
	old_cat = malloc(sizeof(t_cat));
	assert ( old_cat );
	memcpy(old_cat, cat, sizeof(t_cat));
	pthread_create(&thread, &pthread_attr_detach, (void*) data_dump, (void*) old_cat);
	cat = cat->next;
      }
    }
    //    cycle =0;
    // call dump-thread
  } // while (cycle);

  // start cleen-up work
  
  syslog(LOG_NOTICE, "Traff terminated");  
      
  pthread_exit(0);
} // main
//-----------------------------------------------------------------------------------
void catch_signal(int signal) {
  if (signal == SIGUSR1) {
    //prints some debug information
    print_config();
  } else if (signal == SIGHUP) {
    // triggers imidiate Dump
    last_dump = 0;
  } else {
    //causes traff to exit
    cycle = 0;
  }
}
//-----------------------------------------------------------------------------------
void fill_queue(t_interface_list * device) {
  // this functions attaches itself to the device stored in device und starts dumping data into the queue
  char buff[PCAP_ERRBUF_SIZE];
  //unsigned char *raw_pkt;
  //struct pcap_pkthdr pkthdr;
  //t_account account_inf;
  //pthread_t thread;

  // first atach to nic
  DEBUG(printf("Opening Device %s\n",device->name);)
  device->device = pcap_open_live(device->name, 96, 1,100, buff);
  if (! device->device) { 
    printf("Error opening device %s\n",device->name);
    syslog(LOG_ERR, "Error opening device %s",device->name);
    pthread_exit(0); 
  }

  // now start getting the packages
  while (cycle) {
    // get a package
    pcap_dispatch(device->device, -1, (pcap_handler) push_queue, (u_char *) device);
  }
  pthread_exit(0);
}
//---------------------------------------------------------------------------------------------------------------------
void print_config() {
  t_interface_list * devices = config->devices;
  t_cat * cat = config->cats;
  t_ip_filter * filter = 0;
  unsigned char cip[4];
  int i;
  int buffer_free;

  sem_getvalue(&sem_queue_free,&buffer_free);

#if HAVE_LIBMYSQLCLIENT
  printf("Compiled with MySQL support\n");
#endif
#if withPGSQL
  printf("Compiled with PgSQL support\n");
#endif

  printf("Buffer_size: %d\n",config->buffer_size);
  printf("Queue %d%% full\n", (int) ((config->buffer_size - buffer_free)/ config->buffer_size));
  printf("Cycletime: %d\n", config->cycletime);
  printf("Devicecount: %d\n",config->devicecount);
  printf("Devices:\n"); 

  for (i = 0; i < config->devicecount; i++)  {
    printf("| Device: %s\n",devices->name );
    devices = devices->next;
  }

  while (cat) {
    printf("Cat: %s\n",cat->name);
    printf(" Byte Divider: %d\n",cat->bytedivider);
    printf(" Time Divider: %d\n",cat->timedivider);
    printf(" Dump Type: %s\n", get_dump_type_str(cat->dump_type));
    
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
void init_queue(void) {
  DEBUG(printf("Initializing Queue.\n");)
  queue = malloc( config->buffer_size * sizeof(t_raw_data));
  queue_read_pointer = 0;
  queue_write_pointer = 0;
  sem_init(&sem_queue_used, 0, 0);
  sem_init(&sem_queue_free, 0, config->buffer_size);
  memset(queue,0,config->buffer_size * sizeof(t_raw_data));
}
//-----------------------------------------------------------------------------------
void delete_queue(void) {
  //int i;
  queue_read_pointer = -1;
  queue_write_pointer = -1;
  DEBUG(printf("Deleting queue\n");)
    //  for(i = 0;i < buffer_size; i++) {
//  free( queue[i] );
//    queue[i] = 0; 
//  }
  free(queue);
}
//-----------------------------------------------------------------------------------
void push_queue(t_interface_list * device, const struct pcap_pkthdr *h, const u_char *raw_pkt) {
  t_raw_data * data;
  eth_struct_t *eth_pkt = 0;
  ip_struct_t  *ip_pkt  = 0;

  DEBUG(printf("Inserting packet into queue of device %s: wb:%d rb:%d\n",device->name,queue_write_pointer, queue_read_pointer);)
  // Point data to where data should be stored


  if (raw_pkt !=NULL) { // if we receive an empty packet, continue
    eth_pkt = (eth_struct_t *) raw_pkt;
    if (eth_pkt->ptype[0]==8 && eth_pkt->ptype[1] == 0 && h->caplen > (sizeof(ip_struct_t)+14)) {

      sem_wait(&sem_queue_free);
      // This are the packages we are intrested in. This packages should be inserted into the queue for later processong
      // first- get lock on the queue and extract the place where we should store data
      pthread_mutex_lock(&lock_queue);
      data = &(queue[queue_write_pointer]);
      queue_write_pointer = (queue_write_pointer + 1) % config->buffer_size;
      pthread_mutex_unlock(&lock_queue); //Now that we now where to write we can unlock again!

      ip_pkt = (ip_struct_t *) (raw_pkt + 14);                                                    
      //Converts Data:
      DEBUG(printf("IP-Packet %d.%d.%d.%d:%5d -> %d.%d.%d.%d:%5d\n",
            ip_pkt->srcip[0],ip_pkt->srcip[1],ip_pkt->srcip[2],ip_pkt->srcip[3],((ip_pkt->srcpt[0] << 8) + ip_pkt->srcpt[1]),
            ip_pkt->dstip[0],ip_pkt->dstip[1],ip_pkt->dstip[2],ip_pkt->dstip[3],((ip_pkt->dstpt[0] << 8) + ip_pkt->dstpt[1]));)

      data->ip[0]  = ((ip_pkt->srcip[0] << 24) + (ip_pkt->srcip[1] << 16) + (ip_pkt->srcip[2] << 8) + ip_pkt->srcip[3]);
      data->ip[1]  = ((ip_pkt->dstip[0] << 24) + (ip_pkt->dstip[1] << 16) + (ip_pkt->dstip[2] << 8) + ip_pkt->dstip[3]);
      data->port[0]  = ((ip_pkt->srcpt[0] << 8) + ip_pkt->srcpt[1]);
      data->port[1]  = ((ip_pkt->dstpt[0] << 8) + ip_pkt->dstpt[1]);
      data->length = (h->len);
      data->prot  = ip_pkt->prot[0];
      // Increment Write_buffer.
      sem_post(&sem_queue_used);  
    } // its a IP
  } // We have a packet!
}
//-----------------------------------------------------------------------------------
int pop_queue(t_raw_data * dst_data) {
  t_raw_data * data;

  DEBUG(printf("Popping packet from queue\n");)
   
  // wait until there is at least one packet in the queue
  sem_wait(&sem_queue_used);
  //increment read_buffer for next read

  pthread_mutex_lock(&lock_queue);
  data = &(queue[queue_read_pointer]);
  memcpy(dst_data,data,sizeof(t_raw_data));
  queue_read_pointer = (queue_read_pointer + 1) % config->buffer_size;
  pthread_mutex_unlock(&lock_queue); //Now that we now where to write we can unlock again!

  // signal that 1 packet was processed and so one place in buffer is now free
  sem_post(&sem_queue_free);
  return 1;
}
//-----------------------------------------------------------------------------------
/**********************************************************
 * Start of the section responsible for packet-procession *
 * Former data-libary                                     *
 **********************************************************/
//------------------------------------------------------------------------------------
//Following, the macro to exit the next function. as this is needed in varios laces I decided to do i this way.
#define EXIT_DATA_DUMP \

void data_dump(t_cat *cat) {
  // this function will only call the precodure acording to the dumptype
  sem_wait(&sem_dumping);
  dumping++;
  sem_post(&sem_dumping);

  if (cat->dump_type == dt_Stdout) {
    data_stdout_dump(cat);
  } else if (cat->dump_type == dt_Syslog) {
    data_syslog_dump(cat);
  } else if (cat->dump_type == dt_Textfile) {
    data_textfile_dump(cat);
  } else if (cat->dump_type == dt_Binfile) {
    data_binfile_dump(cat);
  } else if (cat->dump_type == dt_Pgsql) {
    data_pgsql_dump(cat);
  } else if (cat->dump_type == dt_Mysql) {
    data_mysql_dump(cat);
  }
  sem_wait(&sem_dumping);
  dumping--;
  sem_post(&sem_dumping);
 
  data_destroy_table(cat->table); 
  free(cat); 
  pthread_exit(0);
}
//------------------------------------------------------------------------------------
int data_mysql_dump (t_cat * cat) {
#if HAVE_LIBMYSQLCLIENT
  t_data * data = 0;
  u_char ips[4]; 
  int bytediv;  
  char timetag[30];
  struct tm *tim;
  size_t i;
  time_t now;

  MYSQL mysql;
  char my_query[QUERYLENGTH];

  DEBUG(printf("Dumping cat %s using mysql\n",cat->name);)

  if(cat->bytedivider > 0) 
    bytediv = cat->bytedivider;
  else
    bytediv = 1;

  now = time(0);
  tim = localtime(&now);
  i = strftime(timetag,30,"%Y-%m-%d",tim);

  bzero(my_query, QUERYLENGTH);
  DEBUG(printf("Initializing Mysql\n");)
  mysql_init(&mysql);
  DEBUG(printf("Connecting to host %s, db %s, table %s using login %s, password %s\n",cat->sql->host,cat->sql->db, cat->sql->table,cat->sql->user,cat->sql->password);)
  mysql_real_connect(&mysql,cat->sql->host,cat->sql->user,cat->sql->password,cat->sql->db,0,NULL,0);
  if (mysql_errno(&mysql)) {
    fprintf(stderr,"Error connecting to Mysql-Database in category %s:\n%d, %s\n",cat->name,  mysql_errno(&mysql),mysql_error(&mysql));
    syslog(LOG_ERR,"Error connecting to Mysql-Database in category %s:\n%d, %s\n",cat->name, mysql_errno(&mysql),mysql_error(&mysql));
    return 1;
  }
  mysql_select_db(&mysql,cat->sql->db); 
  if (mysql_errno(&mysql)) {
    fprintf(stderr,"Error connecting to Mysql-Database in category %s:\n%d, %s\n",cat->name,  mysql_errno(&mysql),mysql_error(&mysql));
    syslog(LOG_ERR,"Error connecting to Mysql-Database in category %s:\n%d, %s\n",cat->name, mysql_errno(&mysql),mysql_error(&mysql));
    return 1;
  }

  DEBUG(printf("Starting dump of each line\n");)
  while ((data = (t_data *) ip_table_fetch_next(cat->table) )) {
    data->input = (int)(data->input / bytediv);
    data->output = (int)(data->output / bytediv);
    if ((data->input == 0) && (data->output == 0)) continue; // we will not dump lines where both counters are null.
    cipa(data->ip, ips);// convert int-ip into quaud-for-notation.
    DEBUG(printf("Dumping ip %d.%d.%d.%d\n",ips[0],ips[1],ips[2],ips[3]);)
    snprintf(my_query,QUERYLENGTH,"UPDATE %s SET input=input+%d,output=output+%d WHERE ip=\"%d.%d.%d.%d\" AND timetag=\"%s\"", cat->sql->table, data->input, data->output, ips[0], ips[1], ips[2], ips[3], timetag);
    DEBUG(printf("Query: %s\n", my_query);)
    
    if (mysql_query(&mysql,my_query)){
      fprintf(stderr,"Error connecting to Mysql-Database in category %s:\n%d, %s\n",cat->name,  mysql_errno(&mysql),mysql_error(&mysql));
      syslog(LOG_ERR,"Error connecting to Mysql-Database in category %s:\n%d, %s\n",cat->name, mysql_errno(&mysql),mysql_error(&mysql));
    }
    DEBUG(printf("Error: %s, Affected Rows: %d\n",mysql_error(&mysql), mysql.affected_rows );)  
    if (! mysql.affected_rows) {
      snprintf(my_query,QUERYLENGTH,"INSERT INTO %s (ip,timetag,input,output) VALUES (\"%d.%d.%d.%d\",\"%s\",%d,%d)", cat->sql->table, ips[0], ips[1], ips[2], ips[3], timetag, data->input, data->output);
      DEBUG(printf("First entry: using query:  %s\n",my_query);)
      mysql_query(&mysql,my_query);
      DEBUG(printf("%s\n",mysql_error(&mysql));)  
    
    }

  }
  DEBUG(printf("Done Dumping\n");)
  mysql_close(&mysql);
  return 0;
#else
  syslog(LOG_ERR,"Error while dumping category %s: Traff was not compiled with MySQL support",cat->name);
  return 1;
#endif
}
//------------------------------------------------------------------------------------
int data_pgsql_dump (t_cat * cat) {
#if withPGSQL
  t_data * data = 0;
  u_char ips[4]; 
  int bytediv;  
  time_t timetag = 1; 

  PGconn * pg_conn;
  PGresult *pg_res;
  char pg_query[QUERYLENGTH];

  if(cat->bytedivider > 0) 
    bytediv = cat->bytedivider;
  else
    bytediv = 1;

  if (cat->timedivider > 0) {
    timetag = (int)(time(0) / cat->timedivider); 
  } else {
    timetag = time(0);
  }

  bzero(pg_query, QUERYLENGTH);
  // If we should dump data to a pgsql-db, then open connection here
  pg_conn = PQsetdbLogin(cat->sql->host,"","",NULL,cat->sql->db,cat->sql->user,cat->sql->password);
  if (PQstatus(pg_conn) == CONNECTION_BAD) {
    syslog(LOG_ERR,"Error in dump of category %s while connecting to PGSQL-Database:\n%s, %s\n", cat->name, PQerrorMessage(pg_conn), PQerrorMessage(pg_conn));
    return 1;
  }
  while ((data = (t_data *) ip_table_fetch_next(cat->table) )) {
    data->input = (int)(data->input / bytediv);
    data->output = (int)(data->output / bytediv);
    if ((data->input == 0) && (data->output == 0)) continue; // we will not dump lines where both counters are null.
    cipa(data->ip, ips);// convert int-ip into quaud-for-notation.
    // do something

      snprintf(pg_query,QUERYLENGTH,"update %s set input=input+%d,output=output+%d where ip=\'%d.%d.%d.%d\' and timetag=%ld",cat->sql->table,data->input,data->output,ips[0],ips[1],ips[2],ips[3],timetag);
      DEBUG(printf("Query: %s\n", pg_query);)
	//First we will try to update an existing entry
      pg_res = PQexec(pg_conn,pg_query);
      if (!pg_res || PQresultStatus(pg_res) != PGRES_COMMAND_OK){
        syslog(LOG_ERR, "Error while dumping category %s: %s",cat->name,PQerrorMessage(pg_conn));
        fprintf(stderr, "Error while dumping category %s: %s",cat->name,PQerrorMessage(pg_conn));
	PQclear(pg_res);
        PQfinish(pg_conn);
        return 1;
      }
      //if update fails, then we should insert.
      if (! atoi(PQcmdTuples(pg_res))) {
      	snprintf(pg_query,QUERYLENGTH,"insert into %s (ip,timetag,input,output) values (\'%d.%d.%d.%d\',%ld,%d,%d)",cat->sql->table,ips[0],ips[1],ips[2],ips[3],timetag,data->input,data->output);
        DEBUG(printf("First entry: using query:  %s\n",pg_query);)
        pg_res = PQexec(pg_conn,pg_query);
        if (!pg_res || PQresultStatus(pg_res) != PGRES_COMMAND_OK){
          syslog(LOG_ERR, "Error while dumping category %s: %s",cat->name,PQerrorMessage(pg_conn));
          fprintf(stderr, "Error while dumping category %s: %s",cat->name,PQerrorMessage(pg_conn));
  	  PQclear(pg_res);
          PQfinish(pg_conn);
          return 1;
	}
      }
  }

  // Close PG-connection if needed
  PQclear(pg_res);
  PQfinish(pg_conn);
  return 0;
#else
  syslog(LOG_ERR,"Error while dumping category %s: Traff was not compiled with PgSQL support",cat->name);
  return 1;
#endif
}
//------------------------------------------------------------------------------------
int data_stdout_dump (t_cat * cat) {
  extern int errno;
  t_data * data = 0;
  //int fifo;
  time_t timetag;
  u_char ips[4]; 
  char timestr[26];
  //FILE * dumpfile;
  int bytediv;  

  if(cat->bytedivider > 0) 
    bytediv = cat->bytedivider;
  else
    bytediv = 1;

  timetag = time(0);
  strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S %z", localtime(&timetag));
  printf("== [ %s ] Starting dump sequence of category %s ==\n", timestr, cat->name);

  if (cat->timedivider > 0) {
    timetag = (int)(time(0) / cat->timedivider); 
  } else {
    timetag = time(0);
  }

  //  data = (t_data *) ip_table_fetch_next(cat->table,0);
  while ( (data = (t_data *) ip_table_fetch_next(cat->table) ) ) {
    data->input = (int)(data->input / bytediv);
    data->output = (int)(data->output / bytediv);
    if ((data->input == 0) && (data->output == 0)) continue; // we will not dump lines where both counters are null.
    cipa(data->ip, ips);// convert int-ip into quaud-for-notation.
    printf("IP: %03d.%03d.%03d.%03d input: %8d output: %8d timetag: %8ld\n",ips[0],ips[1],ips[2],ips[3],data->input,data->output,timetag);
  }
  return 0;
}
//------------------------------------------------------------------------------------
int data_syslog_dump (t_cat * cat) {
  t_data * data = 0;
  time_t timetag;
  u_char ips[4]; 
  int bytediv;  

  if(cat->bytedivider > 0) 
    bytediv = cat->bytedivider;
  else
    bytediv = 1;

  if (cat->timedivider > 0) {
    timetag = (int)(time(0) / cat->timedivider); 
  } else {
    timetag = time(0);
  }

  while ( ( data = (t_data *) ip_table_fetch_next(cat->table) ) ) {
    data->input = (int)(data->input / bytediv);
    data->output = (int)(data->output / bytediv);
    syslog(LOG_NOTICE,"Cat: %s IP: %03d.%03d.%03d.%03d input: %8d output: %8d timetag: %8ld\n",cat->name, ips[0],ips[1],ips[2],ips[3],data->input,data->output,timetag);
  }
  return 0;
}
//------------------------------------------------------------------------------------
int data_textfile_dump (t_cat * cat) {
  extern int errno;
  t_data * data = 0;
  time_t timetag;
  u_char ips[4]; 
  char timestr[100];
  FILE * dumpfile;
  int bytediv;  

  bzero(timestr,100);

  if(cat->bytedivider > 0) 
    bytediv = cat->bytedivider;
  else
    bytediv = 1;

  if (!(dumpfile = fopen(cat->filename,"a"))) {
    syslog(LOG_ERR,"ERROR: Error while category %s dumping into textfile %s: %s",cat->name,cat->filename,strerror(errno));
    return 1;
  }
  timetag = time(0);
  strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S %z", localtime(&timetag));
  fprintf(dumpfile,"== [ %s ] Starting dump sequence of category %s ==\n", timestr, cat->name);
  if (cat->timedivider > 0) {
    timetag = (int)(time(0) / cat->timedivider); 
  } else {
    timetag = time(0);
  }

  while ( ( data = (t_data *) ip_table_fetch_next(cat->table) ) ) {
    data->input = (int)(data->input / bytediv);
    data->output = (int)(data->output / bytediv);
    if ((data->input == 0) && (data->output == 0)) continue; // we will not dump lines where both counters are null.
    cipa(data->ip, ips);// convert int-ip into quaud-for-notation.
    // do something
    fprintf(dumpfile,"Cat: %s IP: %03d.%03d.%03d.%03d input: %8d output: %8d timetag: %8ld\n",cat->name,ips[0],ips[1],ips[2],ips[3],data->input,data->output,timetag);
  }

  fclose(dumpfile);
  return 0;
}
//------------------------------------------------------------------------------------
int data_binfile_dump (t_cat * cat) {
  extern int errno;
  t_data * data = 0;
  time_t timetag;
  u_char ips[4]; 
  FILE * dumpfile;
  int bytediv;  

  if(cat->bytedivider > 0) 
    bytediv = cat->bytedivider;
  else
    bytediv = 1;

  if (!(dumpfile = fopen(cat->filename,"a"))) {
    syslog(LOG_ERR,"ERROR: Error while category %s dumping into textfile %s: %s",cat->name,cat->filename,strerror(errno));
    return 1;
  }

  if (cat->timedivider > 0) {
    timetag = (int)(time(0) / cat->timedivider); 
  } else {
    timetag = time(0);
  }
  while ( ( data = (t_data *) ip_table_fetch_next(cat->table) ) ) {
    data->input = (int)(data->input / bytediv);
    data->output = (int)(data->output / bytediv);
    if ((data->input == 0) && (data->output == 0)) continue; // we will not dump lines where both counters are null.
    cipa(data->ip, ips);// convert int-ip into quaud-for-notation.
    // do something
    fwrite(data, sizeof(t_data),1,dumpfile);
    fwrite(&timetag, sizeof(time_t),1,dumpfile);

  }

  fclose(dumpfile);
  return 0;
}
//------------------------------------------------------------------------------------
void data_destroy_table(void * table) {
  // This function will clean up. It will release the memory allocated by data, ask 
  // ip_table to destroy the table. 

  t_data * data = 0;
  unsigned int ip = 0;
  //unsigned char cip[4];                                                                            

  //fprintf(stderr, "data_destroy_table: Fetching first entry\n");
  //fprintf(stderr, "entries in table: %d\n",ip_table_count(table));
  data = (t_data *) ip_table_fetch_next(table);
  while (data) {
    //lets cycle through the table...
    ip = (data->ip);
    free((t_data *)data); // and free every entry
    ip_table_insert(table,ip,0); // Set the pointer to this entry to 0;
    if (ip != 0xffffffff) {
      ip++;      
      data = (t_data *) ip_table_fetch_next(table);
    } else data = 0;
  }
  // now we can ask ip_table to free the rest
  //fprintf(stderr, "data_destroy_table: passing over to ip_table_destroy_table\n");  
  ip_table_destroy_table(table);
}
//------------------------------------------------------------------------------------
int data_match_rule(t_ip_filter *filter,  t_raw_data * data, int i) {
  //t_ip_filter *tempfilter = filter;

  // cycle through all filters, by return on first match
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
      

  //By default we will return 0. This means, that if no rules are specified,
  //nothing will be accounted.
  return 0; 
}
//-------------------------------------------------------------------------------------
void data_account(t_cat *cat, t_raw_data * data) {
  int i;
  //char cip[4];
  t_data * temp_pkt = NULL;
  
  // check the packet
  // But we have to check in both directions. Once Src-IP being primary and once Dst-IP beeing primary
	if(cat == NULL) printf("cat is NULL!!");

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

  }  //for
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

  data = (t_data *) ip_table_fetch_next(cat->table);
  while (data) {
    ip = (data->ip);
    cipa(ip,cip);
    printf("IP: %03d.%03d.%03d.%03d  input: %8d output %8d\n", cip[0],cip[1],cip[2],cip[3], data->input, data->output);
    
    if (ip != 0xffffffff) {
      ip++;      
      data = (t_data *) ip_table_fetch_next(cat->table);
    } else data = 0;
  }
  
        
}
//----------------------------------------------------------------------------------------------------------------------------
void cipa(unsigned int ip, unsigned char cip[]) {
  cip[0] = ip>>24;
  cip[1] = ((ip<<8)>>24);
  cip[2] = ((ip<<16)>>24);
  cip[3] = ((ip<<24)>>24);
}
//----------------------------------------------------------------------------------------------------------------------------
      
