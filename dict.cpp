#include "utiles.h"
#include <stdio.h>
#include <string.h>

FILE * open_dict( char * dict_file )
{
    FILE * fp = NULL;

    fp = fopen( dict_file, "r" );
    if ( !fp )
    {
        _sshwp_debug( "Open password dictionary(%s) failed.\n", dict_file );
        return NULL;
    }

    return fp;
}

// 返回读取一行字符的长度.
int read_user_info( FILE *fp, PUSR_INF pusr_inf, char * username )
{
    char line[BUFFER_SIZE] = {0};
    // 如果是服务器端关闭了链接，不需要读取字典，该密码组需要重新验证
    if ( pusr_inf->rflag == REMOTE_OPENED )
    {
        if ( fgets( line, BUFFER_SIZE, fp ) == NULL )
        {
            _sshwp_debug( "Read password dictionary failed.\n" );
            fclose( fp );
            return -1;
        }
    }
    else
    {
        pusr_inf->rflag = REMOTE_OPENED;
        return pusr_inf->dict_line_len;
    }

    int r = strlen( line ) + 1;
    pusr_inf->dict_line_len = r;

    char *pcspace = NULL;
    char *pline_feed = NULL;

    pline_feed = strchr( line, '\r' );
    if ( pline_feed )
        *pline_feed = 0;
    pline_feed = strchr( line, '\n' );
    if ( pline_feed )
        *pline_feed = 0;

    pcspace = strchr( line, ' ' );
    if ( pcspace == NULL && username == NULL )
        return -1;

    if ( pcspace == NULL && username != NULL )
    {
        strcpy( pusr_inf->username, username );
        strcpy( pusr_inf->password, pcspace + 1);
    }
    else if ( pcspace )
    {
        *pcspace = 0;
        strcpy( pusr_inf->username, line );
        strcpy( pusr_inf->password, pcspace + 1);
    }

    return r;

}