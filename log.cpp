#include <stdio.h>
#include "utiles.h"
#include <string.h>


int write_ssh_info( char * file, char *hostname, PUSR_INF puser_info )
{
    FILE * fp = fopen( file, "a" );
    if ( fp == NULL )
    {
        _sshwp_debug( "Open Log(%s) failed.", file );
        return -1;
    }

    char buffer[BUFFER_SIZE] = {0};
    sprintf( buffer, "%s:%s/%s\n", 
        hostname, puser_info->username, puser_info->password );

    fwrite( buffer, strlen( buffer ), 1, fp );
    fclose( fp );

    return 0;

}