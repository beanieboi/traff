/*****************************************************************************
 *                       main.c  -  description                              *
 *                       --------------------------------                    *
 *  begin                : Fri Jul 13 2001                                   *
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


//----------------------------------------------------------------------------------
int ip_table_destroy_table(t_IP_MAG * mag, int level) {
  // This function will cycle through the table and destroy it, exept if one ip-entry exists.
  // This means that this modules is not responsible for destroying the data that is stored in the table
  int i;
 
  if (!mag) return 0;
  
  if (level < LEVEL-1) {
    // We arte not at the botton yet!
    for (i = 0; i < IP_MAG_MAX; i++) {
      //fprintf(stderr,"ip_table_destroy_table: level: %d i: %3d mag[i]: %x\n",level,i,mag);
     
      if ((*mag)[i]) {
        // Firts let the recusrsiondestroy any pointer under this level
        ip_table_destroy_table((t_IP_MAG*)(*mag)[i], level+1);
        // now relaese memory an set to null
        //fprintf(stderr,"ip_table_destroy_table: level: %d i: %3d mag[i]: %x -- freeing\n",level,i,mag);
        free((t_IP_MAG*)(*mag)[i]);
        (*mag)[i] = 0;
      }
    }
  } else {
    // Now we are at the botto. All poiunter here are pointers void-poiters to the data stored.
    // If we discover one not-null pointer we will abbort freeing the table as this is not 
    // the duty of this function
    for (i = 0; i < IP_MAG_MAX; i++) {
      //fprintf(stderr,"ip_table_destroy_table: level: %d i: %3d ptr[i]: %x\n",level,i,mag);
      if ((*mag)[i]) {
        fprintf(stderr,"Error: IP_table: Last level with not-null pointer\n");       
        return 1;
      }
    }
  }
  if (level == 0) free((t_IP_MAG*)mag);
  return 0;
}
//----------------------------------------------------------------------------------
t_IP_MAG * ip_table_init() {
  t_IP_MAG * root = malloc(sizeof(t_IP_MAG));
  ip_table_init_mag(root);
  return root;
}
//----------------------------------------------------------------------------------
void * ip_table_fetch_next(t_IP_MAG * root, unsigned int ip){
  unsigned int *next;
  next=malloc(sizeof(unsigned int));
  *next = ip;
  if (!root) return 0;                                                                             
  return ip_table_get_next_entry(root, 0, next); 
  free(next);
}
//----------------------------------------------------------------------------------
void * ip_table_get_next_entry(t_IP_MAG * mag, int level, unsigned int * next) {
// this function cicles trought the mag and gets the next entry.
// It is recursive and will modify global var next!!!
// using next this function remebers the last found ip and starts its search at next +1
//next + 1 is set in fetch_entry(<>)!!!
  unsigned char cip[4];
  int pow,i;
  
  
  if (level >= LEVEL) { return 0; }
  if (mag == 0) { return 0; }

  cipa(*next, cip);
  pow = 1;
  for (i = (LEVEL-1); i > level; i--)
    pow = pow * 256;
        
    // ok, lets start with the last ip that worked for this mag...
  for (i = cip[level]; i < IP_MAG_MAX; i++) {
    ip_table_regen_next(i,level,next);
    ip_table_cipa(*next, cip);
    //printf("inext: i:%3d level:%d ip: %3d.%3d.%3d.%3d\n", i,level, cip[0],cip[1],cip[2],cip[3]);
       
    if ( (level == (LEVEL-1)) && (*mag)[i] ) {
      // found a valid pointer. we can stop our search here :)
      return (void*) (*mag)[i];
    } else if ( (*mag)[i] && (level < (LEVEL-1)) ) {
      // go down another level
      void * val = ip_table_get_next_entry((t_IP_MAG *)(*mag)[i], level + 1,next);
      if (val) {
        // as we fou a valid pointer we can leave this function ...
        return val;
      }
   // ... but if we did not, we will have to search till the end of this mag.
    } // if ( (level == (LEVEL-1)) && (*mag)[i] ) 
  }
  // for next mag of same level to start at 0, we have to set it to zero here. This means
  // that for went strait to the end of this mag, and did not find anything. The next mag of this
  // level must be searched from the beginning.
  ip_table_regen_next(0,level,next);
  
  // and if we find nothing, return 0
  return 0;
  
}
//----------------------------------------------------------------------------------
void ip_table_regen_next(int cip, int level, unsigned int * next) {
  unsigned int i;
  i = 0xff000000>>(level*8);
  i = ~i;
  *next = *next & i;
  cip = cip << ((LEVEL-level-1)*8);
  *next |= cip;
}
//----------------------------------------------------------------------------------
int ip_table_insert(t_IP_MAG * root, unsigned int ip, void * pointer) {
// This function will create all necessary IP-mags, if necessary, and will include the pointer on its possition
  t_IP_MAG * mag = root;
  unsigned char uip[4];
  t_IP_MAG * new_mag = 0;
  int i;
  
  ip_table_cipa(ip, uip); // Convert ip to 4 chars

  #if 0
  printf("Adding: %d.%d.%d.%d\n",uip[0],uip[1],uip[2],uip[3]);
  #endif
  
  if (!mag) return 0;
         
  for (i = 0; i < LEVEL; i++) {
  // Lets cicle throught the levels. If one needed level does not exists it must be createt
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
      // mag for this level does exists, but there is already a value stored!
      //but we will allow it to set the pointer to zero. The other programm has free the pointer before!
      if (! pointer) {      // Overwrite only if suplied pointer is NULL!!!
        (*mag)[uip[i]] = 0;
        return 1;
      }
      return 0;
    } // else if
  } // for

  return 0;
}
//----------------------------------------------------------------------------------
void * ip_table_get_entry(t_IP_MAG * root, unsigned int ip) {
  t_IP_MAG * mag = root;
  unsigned char uip[4];
  int i;
  
  if (!root) return 0;
  
  ip_table_cipa(ip, uip);
  for (i = 0; i < LEVEL; i++) {
    //printf("cip[%d] = %d\n",i, uip[i]);
    if ( !(*mag)[ uip[i] ]) {
      // some of the mags or entry does not exist
      return 0;
    } else if (i < (LEVEL-1)) {
      // go down another level
      mag = (t_IP_MAG*) (*mag)[uip[i]];
    } else if (i == (LEVEL-1)) {
      // Thats it....
      return (*mag)[uip[i]];  
    }
  }
  return 0;
}
//--------------------------------------------------------------------------------------
int ip_table_count(t_IP_MAG * root) {
  return ip_table_count_in_mag((t_IP_MAG *)root, 0);
}
//--------------------------------------------------------------------------------------
int ip_table_count_in_mag(t_IP_MAG * mag, int level) {
  int count;
  int i;
  
  count = 0;
  if (level >= LEVEL) { return 0; }
  if (mag == 0) { return 0; }

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
void ip_table_init_mag ( t_IP_MAG* mag ) {
  int i;
  for (i = 0; i < IP_MAG_MAX; i++ ) {
    (*mag)[i] = 0;
  }
}
//----------------------------------------------------------------------------------
void ip_table_cipa(unsigned int ip, unsigned char cip[]) {
  cip[0] = ip>>24;
  cip[1] = ((ip<<8)>>24);
  cip[2] = ((ip<<16)>>24);
  cip[3] = ((ip<<24)>>24);
}
