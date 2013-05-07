#include "utiles.h"
#include <Windows.h>
#include "stdio.h"
#include <stdarg.h>
#include <process.h>


#define  __DEBUG__

void _sshwp_debug( char * fmt, ... )
{
#ifdef __DEBUG__
    if ( !OPENDEBUG )
        return;

    va_list valist;
    int argn = 0;
    char *para = NULL;

    va_start( valist, fmt );
    //printf("[debug: file: %s, line: %d] ", __FILE__, __LINE__ );
    vprintf( fmt, valist );
    va_end( valist );
#endif

}

void _sshwp_show( char * fmt, ... )
{
    va_list valist;
    int argn = 0;
    char *para = NULL;

    va_start( valist, fmt );
    vprintf( fmt, valist );
    va_end( valist );
}

int node_malloc( PIP_LIST * node )
{
    *node = (PIP_LIST)malloc( sizeof( IP_LIST ) ); 
    if ( * node == NULL )
        return -1;
    return 0;
}
int copy_node( PIP_LIST * node, char * ip )
{
    if ( node_malloc( node ) == 0 )
    {
        strcpy( (*node)->ip, ip );
        return 0;
    }

    return -1;
}

void del_node( PIP_LIST * head, char * ip )
{
    PIP_LIST p;
    PIP_LIST p2;
    PIP_LIST frp = NULL;
    p = *head;
    p2 = p->next;

    if ( strcmp( (*head)->ip, ip ) == 0 )
    {
        frp = *head;
        *head = (*head)->next;
        free(frp);
        return; 
    }

    while( p2->next != NULL )
    {
        if( strcmp( p2->ip, ip ) == 0 )
        {
            frp = p2;
            p->next = p2->next;
            free(frp);
            break;
        }

        p = p->next;
        p2 = p2->next;
    }
}

bool get_one_node( PIP_LIST * head, char *ip )
{
    PIP_LIST p = *head;
    if ( *head )
        strcpy( ip, (*head)->ip );
    else
        return false;

    if ( (*head)->next != NULL )
        *head = (*head)->next;
    else
        *head = NULL;

    if (p)
        free(p);
    return true;
}

int checkip( char * ip )
{
    int i = 0;
    char *p = NULL;
    char ip_check[16] = {0};
    strcpy( ip_check, ip );

    while( (i++) <= 4 )
    {
        p = strchr(ip_check, '.');
        if ( !p )
            return 0;
        p + 1;
        strcpy( ip_check, p );
    }

    return 1;
}

PIP_LIST ipsplit( char * ip_bnet )
{
    char netb[16] = {0};
    char ip[16] = {0};

    strcpy ( netb, ip_bnet );
    char *p = NULL;
    p = strchr( netb, '.' );
    if ( !p )
    {
        _sshwp_debug( "ip parse failed.");
        goto err;
    }

    if ( strchr( p + 1, '.') )
    {
        PIP_LIST t;
        copy_node( &t, ip_bnet );
        t->next = NULL;
        return t; 
    }


    *p = 0;

    int net1 = 0;
    int net2 = 0;

    net1 = atoi( netb );
    net2 = atoi( p + 1 );

    long start = 0;
    long end = 0;

    start = 1  | 0 << 8 | net2 << 16 | net1 << 24;
    end = 255 | 255 << 8 | net2 << 16 | net1 << 24;

    PIP_LIST iphead = NULL;
    PIP_LIST pip = NULL;
    PIP_LIST pip2 = NULL;

    for ( ;start != end;  start++ )
    {
        //if ( (byte)(start) == 255 || (byte)(start) == 0 )
         //   continue;

        sprintf( ip, "%d.%d.%d.%d", 
            (byte)(start >> 24), (byte)(start >> 16),
            (byte)(start >> 8), (byte)(start) );

        // create ip list 
        if ( iphead == NULL )
        {
            if ( copy_node( &pip, ip ) == -1 )
                goto err;
            iphead = pip;
        }
        else
        {
            if ( copy_node( &pip->next, ip ) == -1 ) 
                goto err;
            pip = pip->next;
        }
            
    }

    pip->next = NULL;


    return iphead;


err:
    return NULL;

}