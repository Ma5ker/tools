/**
 * Scanner with connect mode
 * Network code homework
 *	
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
int main(int argc ,char *argv[]){
	if(argc!=2){
			printf("Usage: %s ipaddress\n",argv[0]);
			return 0;
        }
        int s_c;// socket
        struct sockaddr_in server_addr;//target addr
        int err;

        if(s_c<0){
        	printf("socket error\n");
        	return 0;
        }
        bzero(&server_addr,sizeof(server_addr));
        printf("IP\t\tPORT\tInfo\n");
        for(int i=1;i<65535;i++){
        	    s_c=socket(AF_INET,SOCK_STREAM,0);
				 //set 0
				 bzero(&server_addr,sizeof(server_addr));
				 //set address
				 server_addr.sin_family=AF_INET;
				 // target_addr.sin_addr.s_addr=htonl(INADDR_ANY);
				 server_addr.sin_port=htons(i);				/*port*/
				 //change ip to binary
				 inet_pton(AF_INET,argv[1],&server_addr.sin_addr);//ip
				 err=connect(s_c,(struct sockaddr *)&server_addr,sizeof(server_addr));
				 if(err<0){
				 	printf("%s\t%d\trefused\n",argv[1],i );
				 }
				 else{
				 	printf("%s\t%d\taccepted\n", argv[1],i);
				 	if(shutdown(s_c,2)<0){
				 		perror("\nshutdown");
				 		return 0;
				 	}
				}
		        close(s_c);
		}
        printf("--------------------END----------------------\n" );
}
