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

#include <string.h>
#include "readconfig.h"

void config_init(t_config * config,char * filename) {
  
  test_init(config);
}

void test_init(t_config * config) {
  char buff[8];
  t_ip_filter * filtertemp;
  
  config->cycletime = 600; 
  
  //initializing devices
  config->devices = (t_interface_list *) malloc(sizeof(t_interface_list));
  config->devicecount = 1;
  strncpy(config->devices->name,"eth0",TEXTLEN);
  config->devices->next = config->devices;
 
  //initilize list
  config->cats = ( t_cat *) malloc(sizeof(t_cat));
  strncpy(config->cats->name, "WuInt", TEXTLEN);
  config->cats->next = 0;
  config->cats->table = 0;
  config->cats->primary = 0;
  config->cats->secondary = 0;
  config->cats->timedivider = 86400;
  config->cats->bytedivider = 1024; 
  strncpy(config->cats->dump_programm,"traff_stdout_dump", FILELENGTH);
  config->cats->thread = 0;
  
    //now adding some secondary filters
    filtertemp = (t_ip_filter *) malloc(sizeof(t_ip_filter));
    filtertemp->ip   = 0x00000000;
    filtertemp->mask = 0x00000000;
    filtertemp->port = 0;
    filtertemp->prot = 0;
    filtertemp->value = 1;
    filtertemp->next = 0;
    config->cats->secondary = filtertemp;
    //now adding some primary filters
    filtertemp = (t_ip_filter *) malloc(sizeof(t_ip_filter));
    filtertemp->ip   = 0x8d1ee400;
    filtertemp->mask = 0xffffff00;
    filtertemp->port = 0;
    filtertemp->prot = 0;
    filtertemp->value = 1;
    filtertemp->next = 0;
    config->cats->primary = filtertemp;
    
    filtertemp->next = (t_ip_filter *) malloc(sizeof(t_ip_filter));
    filtertemp = filtertemp->next;
    filtertemp->ip   = 0x8d1ee300;
    filtertemp->mask = 0xffffff00;
    filtertemp->port = 0;
    filtertemp->prot = 0;
    filtertemp->value = 1;
    filtertemp->next = 0;
  
    filtertemp->next = (t_ip_filter *) malloc(sizeof(t_ip_filter));
    filtertemp = filtertemp->next;
    filtertemp->ip   = 0x8d1ee200;
    filtertemp->mask = 0xffffff00;
    filtertemp->port = 0;
    filtertemp->prot = 0;
    filtertemp->value = 1;
    filtertemp->next = 0;
 
    filtertemp->next = (t_ip_filter *) malloc(sizeof(t_ip_filter));
    filtertemp = filtertemp->next;
    filtertemp->ip   = 0x8d1edf00;
    filtertemp->mask = 0xffffff00;
    filtertemp->port = 0;
    filtertemp->prot = 0;
    filtertemp->value = 1;
    filtertemp->next = 0;

}
