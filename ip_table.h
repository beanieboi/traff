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

#ifndef IP_TABLE_H
#define IP_TABLE_H


#include <stdio.h>
#include <stdlib.h>
//#include "readconfig.h"

#define IP_MAG_MAX 256
#define LEVEL 4 //do never change this two values!

typedef void* t_IP_MAG[IP_MAG_MAX];

int ip_table_insert(t_IP_MAG * root, unsigned int ip, void * pointer);
t_IP_MAG * ip_table_init(void); 
void ip_table_cipa(unsigned int ip, unsigned char cip[]);
void ip_table_init_mag ( t_IP_MAG* mag );
void * ip_table_get_entry(t_IP_MAG * root, unsigned int ip);
int ip_table_count(t_IP_MAG * root);
int ip_table_insert(t_IP_MAG * root, unsigned int ip, void * pointer);
void ip_table_regen_next(int cip, int level, unsigned int * next);
void * ip_table_get_next_entry(t_IP_MAG * mag, int level, unsigned int * next);
void * ip_table_fetch_next(t_IP_MAG * root, unsigned int ip);
int ip_table_destroy_table(t_IP_MAG * root,int level);


#endif
