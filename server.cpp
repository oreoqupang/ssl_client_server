#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <vector>
#include <algorithm>
#define FAIL	-1

using namespace std;

int broad_cast_mode = 0;
pthread_mutex_t lock;
vector<SSL *> child_fd;

SSL_CTX* InitServerCTX(void)
{
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    const SSL_METHOD * method = TLSv1_2_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}


void* session(void* arg) /* Serve the connection -- threadable */
{
    SSL * ssl = *(SSL**)arg;
    int sd;

    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
	    while (true) {
		const static int BUFSIZE = 1024;
                char buf[BUFSIZE];

                int received = SSL_read(ssl, buf, sizeof(buf));
                if(received <= 0) {
			int err_num = SSL_get_error(ssl, received);
			printf("recv failed or connection over\n");
			break;
		}
			
                buf[received] = '\0';
                printf("%s\n", buf);

		if(broad_cast_mode){
			int err = 0;
			pthread_mutex_lock(&lock);
			for(vector<SSL*>::iterator it = child_fd.begin(); it != child_fd.end(); it++){
				SSL * now_ssl = *it;
				ssize_t sent = SSL_write(now_ssl, buf, strlen(buf));
                        	if (sent <= 0) {
                                	perror("send failed");
                                	err = 1;
					break;
                        	}
			}
			pthread_mutex_unlock(&lock);
			if(err) break;
		}
		else{
			ssize_t sent = SSL_write(ssl, buf, strlen(buf));
			if (sent <= 0) {
				perror("send failed");
				break;
			}
		}
	}
       
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
    return NULL;
}



int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    
    if(argc != 2 && argc != 3){
                printf("syntax : echo_server <port> [-b]\n");
                return -1;
    }

    if(argc == 3){
		if(strcmp(argv[2], "-b")){
			printf("syntax : echo_server <port> [-b]\n");
			return -1;
		}
		broad_cast_mode = 1;
	}

	if (pthread_mutex_init(&lock, NULL) != 0) {
        	perror("mutex init failed");
        	return -1;
	}

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket failed");
		return -1;
	}

	int optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,  &optval , sizeof(int));

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[1]));
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

	int res = bind(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr));
	if (res == -1) {
		perror("bind failed");
		return -1;
	}

	res = listen(sockfd, 5);
	if (res == -1) {
		perror("listen failed");
		return -1;
	}

   
    // Initialize the SSL library
    SSL_library_init();
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    
    while (1)
    {
	    pthread_t tmp;
            struct sockaddr_in addr;
	    SSL * ssl;
            socklen_t clientlen = sizeof(sockaddr);
            int childfd = accept(sockfd, reinterpret_cast<struct sockaddr*>(&addr), &clientlen);
                if (childfd < 0) {
                        perror("ERROR on accept");
                        break;
                }
                printf("Connected: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		ssl = SSL_new(ctx);              /* get new SSL state with context */
        	SSL_set_fd(ssl, childfd);
                if(pthread_create(&tmp, NULL, session,(void *)&ssl)){
                        perror("thread create");
                       return -1;
                }

                pthread_mutex_lock(&lock);
                child_fd.push_back(ssl);
                pthread_mutex_unlock(&lock);
    }

    close(sockfd);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
    pthread_mutex_destroy(&lock);
}
