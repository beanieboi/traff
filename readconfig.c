/*****************************************************************************
 *                       main.c  -  description                              *
 *                       --------------------------------                    *
 *  begin                : Fri Jun 15 13:45:20 CEST 2001                     *
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "readconfig.h"

#define WHITESPACE " \t\r\n"

typedef enum {
  //      oSQL,
      oBadOption,oDevices,oPeriod,oCat,
      oPrimary, oSecondary, oTimeDivider, oByteDivider, oDump, oPackagecount, oBuffersize
} e_opcodes;

static struct {
  const char *name;
  e_opcodes opcode;
} keywords[] = {
  { "devices", oDevices },
  { "period", oPeriod },
  { "cat", oCat },
  { "primary", oPrimary },
  { "secondary", oSecondary },
  { "timedivider", oTimeDivider },
  { "bytedivider", oByteDivider },
  { "dump", oDump },
  { "buffersize", oBuffersize },
  { NULL,0 }
};



//--- Function Prototypes --------------------------------------------------------
char * strdelim(char **s);
static e_opcodes parse_token(const char *cp);
unsigned int ipstrtoint(char * ipstr);
static e_dumptypes parse_dump_token(const char *cp);
//---------------------------------------------------------------------------------
t_config * config_init(t_config * config,char * filename) {

  // initializing config
  config->cycletime = 600;
  config->devices = 0;
  config->cats = 0;
  config->devicecount = 0;
  config->buffer_size = 500;
  
  bzero(conf_file,FILELENGTH);
  strncpy(conf_file,filename,FILELENGTH);
  
  //test_init(config);
  config_read_config_file(config, filename);
  
  return config;
}

//---------------------------------------------------------------------------------
void config_destroy(t_config * config) {


}
//---------------------------------------------------------------------------------
int config_read_config_file(t_config * config,char * filename) {
  //This function will read out Configuration file
  FILE *conf_file;
  char line[1024], *s,*keyword,*arg;
  extern int errno;
  int linenum =0;
  e_opcodes opcode;
  t_cat * cat = 0;
  t_cat * active_cat = 0;
  t_interface_list * new_device = 0;
  t_ip_filter * filter = 0;

  int packagecount = (int)( 0.8 * BUFFERSIZE);
  
  if (!config) return 1;

  
  if (!(conf_file = fopen(filename,"r"))) {
    fprintf(stderr, "Traff: Error opening configuration file %s.\nError: %s\n",filename, strerror(errno));
    exit(1);
  }

  while(fgets(line, sizeof(line), conf_file)) {
    linenum++;
    s = line;
    //printf("%s",line);
    keyword = strdelim(&s);

    /* Ignore leading whitespace. */
    if (*keyword == '\0')
      keyword = strdelim(&s);
    if (!(keyword == NULL || !*keyword || *keyword == '\n' || *keyword == '#')) {
      opcode = parse_token(keyword);
      arg = strdelim(&s);
      switch (opcode) {
        case oBadOption:
          fprintf(stderr,"Traff: Bad Option (%s) in configuration file %s, line %d\n",keyword,filename,linenum);
          break;
        case oDevices:
          if (config->devices) {
            // WE will not allow this Token twice!
            fprintf(stderr,"Traff: Option Devices already declared earlier. Ignoring this one.\n");
            break;                  
          }
          while (!(arg == NULL || !*arg || *arg == '\n' || *arg == '#')) {
            new_device = (t_interface_list *)malloc(sizeof(t_interface_list));
            new_device->device = 0;
            new_device->package_count = packagecount;
	    new_device->thread = (pthread_t *) malloc(sizeof(pthread_t));
            strcpy(new_device->name, arg);
            config->devicecount += 1;
            // first we will insert the devices into this list. Later on, we will make a ring-list of this list
            if (config->devices) {
              //there is already a device. Prepending this one.
              new_device->next = config->devices;
              config->devices = new_device;
            } else {
              //this will be the first device.
              config->devices = new_device;
              new_device->next = 0;  
            }
            arg = strdelim(&s);
          }
          //now we will create the ringlist!
          new_device =  config->devices;
          while (new_device->next)
            new_device = new_device->next;  //arrived at the end of the list
            new_device->next = 0; 
          break;
        case oPeriod:
           config->cycletime = atoi(arg);
           break;
        case oBuffersize:
           config->buffer_size = atoi(arg);
           break;
        case oPackagecount:
           packagecount = atoi(arg);
           if ( packagecount * 0.8 > (int)( 0.8 * BUFFERSIZE)) {
             fprintf(stderr, "Packagecount may not be bigger than %d\n", (int)( 0.8 * BUFFERSIZE));
             packagecount = (int)( 0.8 * BUFFERSIZE);
           }  
           break;


         case oCat:
           active_cat = (t_cat *)malloc(sizeof(t_cat));
           // initializing
           active_cat->primary = 0;
           active_cat->secondary = 0;
           active_cat->bytedivider = 1;
           active_cat->timedivider = 1;
           active_cat->table = 0;
           active_cat->next = 0;
           active_cat->sql = 0;
	   active_cat->dump_type = dt_Stdout;
           strncpy(active_cat->name,arg,TEXTLEN-1);          
           if (config->cats) {
             cat = config->cats;
             while (cat->next)
               cat = cat->next;
             cat->next = active_cat;
           } else {
             config->cats = active_cat;
           }          
           break;
        
        case oPrimary:
        case oSecondary:
           if (! active_cat) {
             fprintf(stderr,"Traff: Reading Cat-option %s outside a Cat, in file %s, line %d.\n",keyword,filename,linenum);
             exit(1);
           }
           if (opcode == oPrimary) filter = active_cat->primary;
           else filter = active_cat->secondary;
           if (filter) {
             while (filter->next)
               filter = filter->next;
             filter->next = (t_ip_filter *) malloc(sizeof(t_ip_filter));
             filter = filter->next;
           } else {
             //first filter in this chain
             filter = (t_ip_filter *) malloc(sizeof(t_ip_filter));
             if (opcode == oPrimary) active_cat->primary = filter; 
             else active_cat->secondary = filter;
           }
           
           //initializing this new filter:
           filter->next = 0;
           // reading policy           
           if (strcasecmp("account",arg) == 0) filter->value=1;
           else if (strcasecmp("ignore",arg) == 0) filter->value=0;
           else {
             fprintf(stderr,"Traff: Reading invalid policy %s, in rule %s, in file %s, line %d.\n",arg,keyword,filename,linenum);
             exit(1);
           }
           //reading ip           
           filter->ip = ipstrtoint(strdelim(&s));
           filter->mask = ipstrtoint(strdelim(&s));
           filter->port = atoi(strdelim(&s));
           break;           
        case oTimeDivider:
           if (! active_cat) {
             fprintf(stderr,"Traff: Reading Cat-option %s outside a Cat, in file %s, line %d.\n",keyword,filename,linenum);
             exit(1);
           }
           active_cat->timedivider = atoi(arg);
           break;           
        case oByteDivider:
           if (! active_cat) {
             fprintf(stderr,"Traff: Reading Cat-option %s outside a Cat, in file %s, line %d.\n",keyword,filename,linenum);
             exit(1);
           }
           active_cat->bytedivider = atoi(arg);
           break;           
        case oDump:
           if (! active_cat) {
             fprintf(stderr,"Traff: Reading Cat-option %s outside a Cat, in file %s, line %d.\n",keyword,filename,linenum);
             exit(1);
           }
	   
	   active_cat->dump_type = parse_dump_token(arg);
	   if ((active_cat->dump_type == dt_Pgsql) || (active_cat->dump_type == dt_Mysql)) { 
             active_cat->sql = (t_sql *) malloc(sizeof(t_sql));
             bzero(active_cat->sql->host, LONGTEXT);
             bzero(active_cat->sql->db, LONGTEXT);
             bzero(active_cat->sql->table, LONGTEXT);
             bzero(active_cat->sql->user, LONGTEXT);
             bzero(active_cat->sql->password, LONGTEXT);
             strncpy(active_cat->sql->host, strdelim(&s),  LONGTEXT);
             strncpy(active_cat->sql->db, strdelim(&s), LONGTEXT);
             strncpy(active_cat->sql->table, strdelim(&s), LONGTEXT);
             strncpy(active_cat->sql->user, strdelim(&s), LONGTEXT);
             strncpy(active_cat->sql->password, strdelim(&s), LONGTEXT);
	   } else if (active_cat->dump_type == dt_Textfile || active_cat->dump_type == dt_Binfile) {
	     active_cat->filename = (char *) malloc(FILELENGTH);
	     strncpy(active_cat->filename, strdelim(&s), FILELENGTH);
	   }
           
           break;
        default:
          fprintf(stderr,"Traff: config_read_config_file: Unimplemented OpCode %d\n",opcode);
      }
    }
  }
  fclose(conf_file);

}       

//---------------------------------------------------------------------------------
unsigned int ipstrtoint(char * ipstr) {
  unsigned int i = 0;
  char cip1[4], cip2[4],cip3[4],cip4[4];
  sscanf(ipstr,"%[0-9].%[0-9].%[0-9].%[0-9]", cip1, cip2, cip3, cip4);
  i = atoi(cip1) << 24;
  i += atoi(cip2) << 16;
  i += atoi(cip3) << 8;
  i += atoi(cip4);
  return i;
}
//---------------------------------------------------------------------------------
static e_dumptypes parse_dump_token(const char *cp){
  unsigned int i;
  for (i = 0; dump_types[i].name; i++)
    if (strcasecmp(cp, dump_types[i].name) == 0)
       return dump_types[i].dump_type;
                
  return dt_BadOption;
}
//--------------------------------------------------------------------------------
char * get_dump_type_str(e_dumptypes dumptype) {
  unsigned int i;
  char * charBadOption;
  for (i = 0; keywords[i].name; i++) {
    if (dumptype == dump_types[i].dump_type) 
       return (char *) dump_types[i].name;
    if (dt_BadOption == dump_types[i].dump_type)
      charBadOption = (char *) dump_types[i].name;
  }
  return charBadOption;
}
//---------------------------------------------------------------------------------
static e_opcodes parse_token(const char *cp) {
  unsigned int i;
  for (i = 0; keywords[i].name; i++)
    if (strcasecmp(cp, keywords[i].name) == 0)
       return keywords[i].opcode;
                   
  return dt_BadOption;
}
//---------------------------------------------------------------------------------
char * strdelim(char **s) {
  char *old;
  int wspace = 0;
  if (*s == NULL)
    return NULL;
  
  old = *s;
  *s = strpbrk(*s, WHITESPACE "=");
  if (*s == NULL)
    return (old);
                                                     
  /* Allow only one '=' to be skipped */
  if (*s[0] == '=')
  wspace = 1;
  *s[0] = '\0';
  *s += strspn(*s + 1, WHITESPACE) + 1;
  if (*s[0] == '=' && !wspace)
  *s += strspn(*s + 1, WHITESPACE) + 1;
  return (old);
}

