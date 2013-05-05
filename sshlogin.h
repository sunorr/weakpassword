#ifndef __SSHLOGIN_H__
#define __SSHLOGIN_H__


extern CRITICAL_SECTION g_CriticalSection_write;
extern CRITICAL_SECTION g_CriticalSection_ssh_init;


int ssh_login( char *hostname, char *username, char *password, int port = 22 );
int guss_ssh_passwd( char *hostname, int port = 22, char *dict_file = "data", char *log = NULL, int timeout = 3 );

#endif