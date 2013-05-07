#ifndef __UTILES_H__
#define __UTILES_H__
//#define __DEBUG__

#include <stdio.h>
#include <process.h>

#ifdef __cplusplus
extern "C" { 
#endif 

#define BUFFER_SIZE  512
#define USERNAME_LEN 32
#define PASSWORD_LEN 32



extern int OPENDEBUG;

typedef struct _ip_list
{
    char ip[16];
    _ip_list * next;
}IP_LIST, *PIP_LIST;

#define REMOTE_CLOSED  1
#define REMOTE_OPENED  0
typedef struct _usr_inf
{
    char  username[USERNAME_LEN];
    char  password[PASSWORD_LEN];
    unsigned char rflag;
    int dict_line_len;
}USR_INF, *PUSR_INF;

void _sshwp_debug( char * fmt, ... );
void _sshwp_show( char * fmt, ... );
// 打开字典文件
FILE * open_dict( char * dict_file );
// 读取字典文件, 并获取字典用户名密码
int read_user_info( FILE *fp, PUSR_INF pusr_inf, char * username = NULL );

PIP_LIST ipsplit( char * ip_bnet );
bool get_one_node( PIP_LIST *, char * );

#ifdef __cplusplus
}
#endif 

#endif
