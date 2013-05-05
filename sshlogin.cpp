//#include <Windows.h>
#include <WinSock2.h>
#include <libssh2.h>
#include "utiles.h"
#include "log.h"

#pragma comment( lib, "libssh2" )
#pragma comment( lib, "Ws2_32" )



CRITICAL_SECTION g_CriticalSection_write;
CRITICAL_SECTION g_CriticalSection_ssh_init;

typedef struct _ssh_session
{
    int sock;
    LIBSSH2_SESSION *session;
}SSH_SESSION, *PSSH_SESSION ;


void close_sshsession( PSSH_SESSION  pss )
{
    if ( pss )
    {
        if ( pss->session )
        {
            libssh2_session_disconnect( pss->session, "" );
            libssh2_session_free( pss->session );
        }

        unsigned long im = 0;
        ioctlsocket( pss->sock, FIONBIO, &im );

        closesocket( pss->sock );
        libssh2_exit();
        free( pss );
    }
}
// 准备ssh连接需要的tcp连接.
int prepare_ssh_session( char * hostname, PSSH_SESSION * pss, int port = 22, int timeout = 3 )
{

    WSADATA wsadata;
    WSAStartup( MAKEWORD( 2, 0 ), &wsadata );

    EnterCriticalSection( &g_CriticalSection_ssh_init );
    int rc = libssh2_init( 0 );
    LeaveCriticalSection( &g_CriticalSection_ssh_init );
    if ( rc != 0 )
    {
        _sshwp_debug( "libssh2 initialization failed (%d)!\n", rc );
        return -1;
    }

    unsigned long hostaddr = inet_addr( hostname );
    int sock = socket( AF_INET, SOCK_STREAM, 0 );
    if ( sock == INVALID_SOCKET )
    {
        _sshwp_debug( "socket init failed (%d)!\n", WSAGetLastError() );
        return -1;
    }

    unsigned long im = 1;
    // 设置socket为非阻塞模式
    ioctlsocket( sock, FIONBIO, &im );

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons( port );
    sin.sin_addr.s_addr = inet_addr( hostname );

    

    /*
    if ( connect( sock, 
        ( struct sockaddr * )( &sin ), 
        sizeof(struct sockaddr_in) ) != 0 )
    {
        _sshwp_debug( "connect %s ssh port(%d) failed!\n", hostname, port );
        closesocket( sock );
        return -1;
    }
    */
    timeval tm;
    fd_set set;
    int error = -1;

    if ( connect( sock, 
        ( struct sockaddr * )( &sin ), 
        sizeof(struct sockaddr_in) ) == -1 )
    {
        tm.tv_sec = timeout;
        tm.tv_usec = 0;
        FD_ZERO( &set );
        FD_SET( sock, &set );
        if ( select( sock + 1, NULL, &set, NULL, &tm ) != 1  )
        {
            _sshwp_debug( "connect %s ssh port(%d) failed!\n", hostname, port );
            im = 0;
            ioctlsocket( sock, FIONBIO, &im );
            closesocket( sock );
            return -1;

        }


    }

    LIBSSH2_SESSION *session;
    session = libssh2_session_init();
    if ( !session )
    {
        _sshwp_debug( "libssh2 session init failed!\n" );
        return -1;
    }

    // non-blocking
    libssh2_session_set_blocking( session, 0 );

    // ssh handshake
    while ( ( rc = libssh2_session_handshake( session, sock ) ) == 
        LIBSSH2_ERROR_EAGAIN );
    if ( rc )
    {
        _sshwp_debug( "Failure establishing SSH session: %d\n", rc );
        return -1;
    }


    *pss = ( PSSH_SESSION )malloc( sizeof( SSH_SESSION ) );
    if ( !pss )
        return -1;
    (*pss)->session = session;
    (*pss)->sock = sock;

    return 0;

}

int guss_ssh_passwd( char *hostname, int port = 22, char *dict_file = "data", char *log = NULL, int timeout = 3 )
{
    PSSH_SESSION pss = NULL;
    PUSR_INF puser_info = NULL;

    puser_info = ( PUSR_INF )malloc( sizeof(USR_INF) );
    if ( !puser_info )
        return -1;

    // 如果连接不成功就不打开文件, 不然该文件被打开次数太多会出错.
    FILE * fp = NULL;
    if ( prepare_ssh_session( hostname, &pss, port, timeout ) == 0 )
    {
        fp = open_dict( dict_file );
        if ( !fp )
        {
            free( puser_info );
            return -1;
        }
    }
    else
        return -1;


    int rc = 0;
    // 记录字典读取的状态
    int rdict = 0;

    while ( 1 )
    {

        // 一个ssh session允许输入错误密码次数为 3-5 次, 避免重新创建
        // 登录ssh的session 
        while ( ( rdict = read_user_info( fp, puser_info ) ) != -1 )
        {
            while ( ( rc = libssh2_userauth_password( 
                            pss->session, 
                            puser_info->username,
                            puser_info->password ) ) == 
                      LIBSSH2_ERROR_EAGAIN );

           

            if ( rc == 0 )
            {
                // TODO: 猜到密码后是否需要继续再猜?????
                _sshwp_show( "host:%-15s\t user:%-16s\t password:%-16s\n", 
                              hostname, 
                              puser_info->username, 
                              puser_info->password );
                break;
            }
            // TODO 如果非密码验证的错误, 需要重新验证密码
            else if ( rc == LIBSSH2_ERROR_AUTHENTICATION_FAILED )
            {
                _sshwp_debug( "Authentication by password failed.(%d)\n", rc );
                continue;
            }
            else
            {
                _sshwp_debug( "SSH session closed. (%d)\n", rc );
                break;
            }
        }

        close_sshsession( pss );
        pss = NULL;

        if ( rdict != -1 && rc != LIBSSH2_ERROR_AUTHENTICATION_FAILED )
            fseek( fp, 0 - rdict, SEEK_CUR );

        if ( rc == 0 || rdict == -1 )
            break;

        if ( prepare_ssh_session( hostname, &pss, port ) != 0 )
        {
            fclose(fp);
            free( puser_info );
            return -1;
        }

    }

    fclose( fp );
    if ( log )
    {
        EnterCriticalSection( &g_CriticalSection_write );
        write_ssh_info( log, hostname, puser_info );
        LeaveCriticalSection( &g_CriticalSection_write );
    }

    free( puser_info );
    return 0;
}

int ssh_login( char *hostname, char *username, char *password, int port = 22 )
{
    WSADATA wsadata;
    WSAStartup( MAKEWORD( 2, 0 ), &wsadata );

    int rc = libssh2_init( 0 );
    if ( rc != 0 )
    {
        _sshwp_debug( "libssh2 initialization failed (%d)!\n", rc );
        return -1;
    }

    unsigned long hostaddr = inet_addr( hostname );
    int sock = socket( AF_INET, SOCK_STREAM, 0 );
    if ( sock == INVALID_SOCKET )
    {
        _sshwp_debug( "socket init failed (%d)!\n", WSAGetLastError() );
        return -1;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons( port );
    sin.sin_addr.s_addr = inet_addr( hostname );

    if ( connect( sock, 
        ( struct sockaddr * )( &sin ), 
        sizeof(struct sockaddr_in) ) != 0 )
    {
        _sshwp_debug( "connect ssh port(%d) failed!\n", port );
        return -1;
    }

    LIBSSH2_SESSION *session;
    session = libssh2_session_init();
    if ( !session )
    {
        _sshwp_debug( "libssh2 session init failed!\n" );
        return -1;
    }

    // non-blocking
    libssh2_session_set_blocking( session, 0 );

    // ssh handshake
    while ( ( rc = libssh2_session_handshake( session, sock ) ) == 
              LIBSSH2_ERROR_EAGAIN );
    if ( rc )
    {
        _sshwp_debug( "Failure establishing SSH session: %d\n", rc );
        return -1;
    }



    while ( ( rc = libssh2_userauth_password( session, 
                                              username,
                                              password ) ) == 
              LIBSSH2_ERROR_EAGAIN );
    if ( rc )
    {
        switch ( rc )
        {
        case LIBSSH2_ERROR_SOCKET_SEND:
            _sshwp_debug( "Socket send failed.(%d)\n", rc );
            break;

        case LIBSSH2_ERROR_TIMEOUT:
            _sshwp_debug( "Timeout.(%d)\n", rc );
            break;

        default:
            _sshwp_debug( "Authentication by password failed.(%d)\n", rc );
            Sleep( 1000 );
            break;
        }
        goto shutdown;
    }

shutdown:
    libssh2_session_disconnect( session, "" );
    libssh2_session_free( session );
    closesocket( sock );
    libssh2_exit();

    return 0;
}