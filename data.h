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

#ifndef DATA_H
#define DATA_H


#include <stdio.h>
#include <stdlib.h>
//#include <sys/types.h>
//#include <string.h>
//#include <pcap.h>
//#include <signal.h>
//#include <limits.h>
//#include <unistd.h>
//#include <fcntl.h>
//#include <time.h>
//#include <netinet/in.h>
#include "readconfig.h"


void data_account(t_cat *cat, t_raw_data * data);
void data_cipa(unsigned int ip, unsigned char cip[]);
int data_match_rule(t_ip_filter *filter,  t_raw_data * data, int i);
void data_print_info(t_cat *cat);
void data_destroy_table(void *table);
void data_dump(t_cat *cat);


#endif
