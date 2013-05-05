#ifndef  __LOG_H__
#define  __LOG_H__
#include "utiles.h"

// 将破解的密码写入文件
int write_ssh_info( char * file, char *hostname, PUSR_INF puser_info );
#endif