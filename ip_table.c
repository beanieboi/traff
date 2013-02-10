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
//#include <sys/types.h>
//#include <string.h>
//#include <pcap.h>
//#include <signal.h>
//#include <limits.h>
//#include <unistd.h>
//#include <fcntl.h>
//#include <time.h>
//#include <netinet/in.h>
//#include "readconfig.h"
#include "ip_table.h"
//void cipa(unsigned int ip, unsigned char cip[]);

//#define DEBUG(s) printf("traff(%d): ",getpid()); s;
#define DEBUG(s)

//----------------------------------------------------------------------------------
int ip_table_destroy_table(t_table * table)
{
    t_IP_MAG * root;
    unsigned char cip[4];
    int i0,i1,i2,i3;
    t_IP_MAG *l1, *l2,*l3;

    root = table->table;
    cipa(table->next, cip);


    for (i0 = cip[0]; i0 < 256; i0++) {
        if ((*root)[i0] == 0) continue;
        l1 = (*root)[i0];
        for (i1 = cip[1]; i1 < 256; i1++) {
            if ((*l1)[i1] == 0) continue;
            l2 = (*l1)[i1];
            for (i2 = cip[2]; i2 < 256; i2++) {
                if ((*l2)[i2] == 0) continue;
                l3 = (*l2)[i2];
                for (i3 = cip[3]; i3 < 256; i3++) {
                    if ((*l3)[i3] == 0) continue;
                    free((*l3)[i3]);
                }
                cip[3] = 0;
                free(l3);
            }
            cip[2] = 0;
            free(l2);
        }
        cip[3] = 0;
        free(l1);
    }
    free(table->table);
    free(table);
    return 0;
}
//----------------------------------------------------------------------------------
t_table * ip_table_init()
{
    t_table * table;
    table = malloc(sizeof(t_table));
    table->table = malloc(sizeof(t_IP_MAG));
    ip_table_init_mag(table->table);
    table->next = 0;
    return table;
}
//----------------------------------------------------------------------------------
void * ip_table_fetch_next(t_table * table)
{
    t_IP_MAG * root;
    unsigned char cip[4];
    int i0,i1,i2,i3;
    t_IP_MAG *l1, *l2,*l3;


    root = table->table;
    cipa(table->next, cip);
    i0 = cip[0];
    i1 = cip[1];
    i2 = cip[2];
    i3 = cip[3];

    for (i0 = cip[0]; i0 < 256; i0++) {
        DEBUG(printf("fetchnext: level: 1 i0: %3d i1: %3d, i2: %3d i3: %3d\n", i0, i1, i2, i3);)
        if ((*root)[i0] == 0) continue;
        l1 = (*root)[i0];
        for (i1 = cip[1]; i1 < 256; i1++ ) {
            DEBUG(printf("fetchnext: level: 2 i0: %3d i1: %3d, i2: %3d i3: %3d\n", i0, i1, i2, i3);)
            if ((*l1)[i1] == 0) continue;
            l2 = (*l1)[i1];
            for (i2 = cip[2]; i2 < 256; i2++) {
                DEBUG(printf("fetchnext: level: 3 i0: %3d i1: %3d, i2: %3d i3: %3d\n", i0, i1, i2, i3);)
                if ((*l2)[i2] == 0) continue;
                l3 = (*l2)[i2];
                for (i3 = cip[3]; i3 < 256; i3++) {
                    DEBUG(printf("fetchnext: level: 4 i0: %3d i1: %3d, i2: %3d i3: %3d\n", i0, i1, i2, i3);)
                    if ((*l3)[i3] == 0) continue;
                    table->next = (i0 << 24) + (i1 << 16) + (i2 << 8) + i3 + 1;
                    return (*l3)[i3];
                }
                cip[3] = 0;
            }
            cip[2] = 0;
            cip[3] = 0;
        }
        cip[1] = 0;
        cip[2] = 0;
        cip[3] = 0;
    }
    table->next = 0;
    return 0;
}
//----------------------------------------------------------------------------------
int ip_table_insert(t_table * table, unsigned int ip, void * pointer)
{
    t_IP_MAG * root;
// This function will create all necessary IP-mags, if necessary, and will include the pointer on its possition
    t_IP_MAG * mag;
    unsigned char uip[4];
    t_IP_MAG * new_mag = 0;
    int i;

    root = table->table;
    mag = root;

    cipa(ip, uip); // Convert ip to 4 chars

//  printf("Adding: %d.%d.%d.%d\n",uip[0],uip[1],uip[2],uip[3]);

    if (!mag) return 0;

    for (i = 0; i < LEVEL; i++) {
        // Let's cycle through the levels. If one needed level does not exists it must be created.
        //   printf("\nLevel: %d  uip.cip[%d]: %d  (*mag)[uip.cip[i]]: %x -->",i ,i, uip[i],(*mag)[uip[i]]);
        if ( (!(*mag)[uip[i]]) && (i < LEVEL-1) ) {
            // a new level has to be created
            new_mag = (t_IP_MAG*) malloc(sizeof(t_IP_MAG));
            ip_table_init_mag(new_mag);
            (*mag)[uip[i]] = new_mag;
//    printf("%x",(*mag)[uip[i]]);
            mag = (t_IP_MAG*) new_mag;
            new_mag=0;
        } else if ( ((*mag)[uip[i]]) && (i < LEVEL-1)) {
            // there is another mag under it....
            mag = (t_IP_MAG*) (*mag)[uip[i]];
        } else if( (!(*mag)[uip[i]]) && (i == (LEVEL-1))) {
            // insert pointer
            (*mag)[uip[i]] = pointer;
//    printf("(%x)\n",pointer);
            return 1;
        } else {
            // mag for this level does exist, but there is already a value stored!
            //but we will allow it to set the pointer to zero. The other programm has free the pointer before!
            if (! pointer) {      // Overwrite only if supplied pointer is NULL!!!
                (*mag)[uip[i]] = 0;
                return 1;
            }
            return 0;
        } // else if
    } // for

    return 0;
}
//----------------------------------------------------------------------------------
void * ip_table_get_entry(t_table * table, unsigned int ip)
{
    t_IP_MAG * root;
    t_IP_MAG * mag;

    unsigned char uip[4];
    int i;

    root = table->table;
    mag = root;

    if (!root) {
        return NULL;
    }

    cipa(ip, uip);
    for (i = 0; i < LEVEL; i++) {
//    printf("cip[%d] = %d\n",i, uip[i]);
        if ( !(*mag)[ uip[i] ]) {
            // some of the mags or entry does not exist
            return NULL;
        } else if (i < (LEVEL-1)) {
            // go down another level
            mag = (t_IP_MAG*) (*mag)[uip[i]];
        } else if (i == (LEVEL-1)) {
            // That's it....
            return (*mag)[uip[i]];
        }
    }
    return NULL;
}
//--------------------------------------------------------------------------------------
int ip_table_count(t_table * table)
{
    t_IP_MAG * root;
    root = table->table;
    return ip_table_count_in_mag((t_IP_MAG *)root, 0);
}
//--------------------------------------------------------------------------------------
int ip_table_count_in_mag(t_IP_MAG * mag, int level)
{
    int count;
    int i;

    count = 0;
    if (level >= LEVEL) {
        return 0;
    }
    if (mag == 0) {
        return 0;
    }

    for (i = 0; i < IP_MAG_MAX; i++) {
        if ( (level == (LEVEL-1)) && (*mag)[i] ) {
            // found one!
// //     printf("Found entry %x in level %d, entry %d\n",(*mag)[i], level, i);
            count++;
        } else if ( (*mag)[i] && (level < (LEVEL-1)) ) {
//      printf("Entring in %x in level %d, entry %d\n",(*mag)[i], level, i);
            count += ip_table_count_in_mag((t_IP_MAG *)(*mag)[i], level+1);
        }
    }
    return count;
}
//--------------------------------------------------------------------------------------
void ip_table_init_mag ( t_IP_MAG* mag )
{
    int i;
    for (i = 0; i < IP_MAG_MAX; i++ ) {
        (*mag)[i] = NULL;
    }
}
//----------------------------------------------------------------------------------
/*void cipa(unsigned int ip, unsigned char cip[]) {
  cip[0] = ip>>24;
  cip[1] = ((ip<<8)>>24);
  cip[2] = ((ip<<16)>>24);
  cip[3] = ((ip<<24)>>24);
  }*/

