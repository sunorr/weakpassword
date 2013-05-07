#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <ctype.h>
#include <conio.h>
#include "getopt.h"
#include "utiles.h"
#include "sshlogin.h"
#include <process.h>


PIP_LIST ip_list = NULL;
#define  MAX_THREAD  1000

CRITICAL_SECTION CriticalSection_list;

float ip_sum = 65536;
float ip_complete = 0;

void help( char * exename )
{
    printf( "Usage: %s [OPTIONS]\n" 
        "   -h, <host>        appoint the host ip to scan.\n"
        "       Example: %s -h 192.168\n"
        "   -D                debug mode.\n"
        "   -p, <port>        appoint the port to scan.\n"
        "   -t  <thread NO.>  indicate how many thread to be scanned.\n"
        "   -x  <file name>   indicate where is stored the result.\n"
        "   -o  <timeout>     indicate the timeout of the connection.\n"
        /*
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        ""
        ""
        ""
        ""
        ""
        ""
        ""
        ""
        "",
        */
        ,exename, exename
        );
    exit( 1 );

}

typedef struct thread_args
{
    char ip[16];
    int port;
    int timeout;
    char dictionary[MAX_PATH];
    char password[MAX_PATH];

}THREAD_ARGS, *PTHREAD_ARGS;

// call back of thread
UINT __stdcall guss_passwd( void * argument )
{
    char ip[16] = {0};
    PTHREAD_ARGS args = (PTHREAD_ARGS)argument;
    while ( 1 )
    {
        EnterCriticalSection( &CriticalSection_list );
        if ( !get_one_node( &ip_list, ip ) )
        {
            LeaveCriticalSection( &CriticalSection_list );
            goto err;
        }
        else
        {
            ip_complete++;
        }
        LeaveCriticalSection( &CriticalSection_list );
        guss_ssh_passwd( ip, args->port, args->dictionary, args->password, args->timeout );

        _sshwp_show( "%8.2f%%", ip_complete / ip_sum * 100 );
        _sshwp_show( "\b\b\b\b\b\b\b\b\b" );
    }

err:
    _endthreadex( 0 );
    return 0;
}

int OPENDEBUG = 0;

int main( int argc, char *argv[] )
{
    int c = 0;
    OPENDEBUG = 0;

    THREAD_ARGS args = {0};
    int thread_num = 512;
    args.port = 22;
    strcpy( args.dictionary, "data" );
    char ip_net[16] = {0};

    while ( ( c = getopt( argc, argv, "h:Dd:p:t:x:o:") ) != -1 )
    {
        switch( c )
        {
        // ip段
        case 'h':
            strncpy( ip_net, optarg, 16 );
            break;

        // Debug 模式
        case 'D':
            OPENDEBUG = 1;
            break;

        // 密码字典
        case 'd':
            strcpy( args.dictionary, optarg );
            break;

        // 猜测端口
        case 'p':
            args.port = atoi( optarg );
            break;

        // 线程数量
        case 't':
            thread_num = atoi( optarg );
            break;

        // 破解password记录文件
        case 'x':
            strcpy( args.password, optarg );
            break;

        // 超时
        case 'o':
            args.timeout = atoi( optarg );
            break;


        default:
            help( argv[0] );
            break;

        }

    }

    if ( ip_net[0] == 0 )
        help( argv[0] );

    if ( args.password[0] == 0 )
        strcpy( args.password, ip_net );

    if ( _access( args.password, 0 ) != -1 )
    {
        _sshwp_show( "The password file : %s is exists, do you want to recreate it?[y/n]", args.password );
        if ( _getch() == 'y' )
            fopen( args.password, "w" );
        else
            exit( -1 );
    }

    if ( thread_num > MAX_THREAD )
        thread_num = MAX_THREAD;

    if ( args.timeout == 0 )
        args.timeout = 3;

    

    ip_list = ipsplit( ip_net );



    HANDLE *thread_handles = (HANDLE *)malloc( sizeof(HANDLE) * thread_num);
    if ( ! thread_handles )
        return -1;

    InitializeCriticalSection( &CriticalSection_list ); 
    InitializeCriticalSection( &g_CriticalSection_write ); 
    InitializeCriticalSection( &g_CriticalSection_ssh_init ); 

    //guss_ssh_passwd( "192.168.1.120" );
    unsigned threadid;
    int i = 0;

    _sshwp_show( "\nprogress: " );
    for ( i = 0; i < thread_num; i++ )
    {
        thread_handles[i] =
            (HANDLE)_beginthreadex( NULL, NULL, guss_passwd, &args, 0, &threadid );
    }
    for ( i = 0; i < thread_num; i++ )
    {
        if ( thread_handles[i] != 0 )
        {
            WaitForSingleObject( thread_handles[i], INFINITE );
            CloseHandle( thread_handles[i] );
        }
    }
    /*
    while ( thread_num != 0 )
    {
        _beginthread( guss_passwd, 0, NULL );
        Sleep( 100 );
        thread_num--;
    }
    */

    //DeleteCriticalSection( &CriticalSection );
    free( thread_handles );
    return 0 ;

}


