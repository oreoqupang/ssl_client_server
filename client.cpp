#include <stdio.h> // for perror
#include <stdlib.h>
#include <string.h> // for memset
#include <unistd.h> // for close
#include <arpa/inet.h> // for htons
#include <netinet/in.h> // for sockaddr_in
#include <sys/socket.h> // for socket
#include <pthread.h>
#include <sys/time.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL	-1


SSL_CTX* InitCTX(void)
{
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    const SSL_METHOD * method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void * recv_thread(void * arg){
	SSL* ssl = *(SSL **)arg;
	int sd;

	const static int BUFSIZE = 1024;
        char buf[BUFSIZE];
	
	while(true){
			int received = SSL_read(ssl, buf, BUFSIZE - 1);
			if(received == 0){
				perror("eof");
				break;
			}
			
			if (received == -1) {
                        	perror("recv failed");
				break;
                	}
			buf[received] = '\0';
                	printf("%s\n", buf);

	}
	sd = SSL_get_fd(ssl);       /* get socket connection */
    	SSL_free(ssl);         /* release SSL state */
    	close(sd); 
	return NULL;
}


int main(int argc, char * argv[]) {
	if(argc != 3){
		printf("syntax : echo_client <host> <port>\n");
		return -1;
	}
	SSL_CTX * ctx;
	SSL * ssl;

	SSL_library_init();
	ctx = InitCTX();
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket failed");
		return -1;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[2]));
	inet_aton(argv[1], &addr.sin_addr);
	memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

	int res = connect(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr));
	if (res == -1) {
		perror("connect failed");
		return -1;
	}

	ssl = SSL_new(ctx);      /* create new SSL connection state */
    	SSL_set_fd(ssl, sockfd);    /* attach the socket descriptor */
    	if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        	ERR_print_errors_fp(stderr);
    	else
    	{
		printf("connected\n");
		pthread_t tid;

		if(pthread_create(&tid, NULL, recv_thread, (void*)&ssl)){
			perror("thread create");
			return -1;
		}

		while (true) {
			const static int BUFSIZE = 1024;
			char buf[BUFSIZE];

			fgets(buf, BUFSIZE, stdin);
			buf[strlen(buf)-1] = 0;
		
			if (strcmp(buf, "quit") == 0) break;

			ssize_t sent = SSL_write(ssl, buf, strlen(buf));
			if (sent == 0) {
				perror("send failed");
				break;
			}
		}
	}
	close(sockfd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
}
