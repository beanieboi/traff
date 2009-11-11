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

//#include "data.h"
//#include "readconfig.h"

#define IP_MAG_MAX 256
#define LEVEL 4 //do never change these two values!

typedef void* t_IP_MAG[IP_MAG_MAX];

typedef struct t_table {
  t_IP_MAG* table;
  unsigned int next;
} t_table;

t_table * ip_table_init(void); 

//void ip_table_cipa(unsigned int ip, unsigned char cip[]);
void ip_table_init_mag ( t_IP_MAG* mag );
void * ip_table_get_entry(t_table * table, unsigned int ip);
int ip_table_count(t_table * table);
int ip_table_insert(t_table * table, unsigned int ip, void * pointer);
int ip_table_destroy_table(t_table * table);
int ip_table_count_in_mag(t_IP_MAG * mag, int level);
void cipa(unsigned int ip, unsigned char cip[]);
//void ip_table_regen_next(int cip, int level, unsigned int * next);
//void * ip_table_get_next_entry(t_IP_MAG * mag, int level, unsigned int * next);
//void * ip_table_fetch_next(table * tableroot, unsigned int ip);
void * ip_table_fetch_next(t_table * table);

#endif
