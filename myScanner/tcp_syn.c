/**
 * Scanner with tcp SYN mode
 * Network code homework
 * 丢包严重
 *  
 */
#include <stdio.h> 
#include <stdlib.h> 
#include<fcntl.h>   
#include <signal.h>
#include <netdb.h>  
#include <string.h>  
#include <unistd.h>  
#include <sys/socket.h>  
#include <sys/types.h>  
#include <netinet/in.h>  
#include <netinet/ip.h>  
#include <linux/tcp.h>  
#include <errno.h>  
#include<pthread.h>  
#include <net/if_arp.h>
#include <arpa/inet.h>  
#include <linux/if.h>
#include <linux/sockios.h>

/* target address*/  
struct sockaddr_in target;  
/*my address*/
struct sockaddr_in myaddr;
/* file handle*/  
int sock ;  
/*thread handle*/
pthread_t thread ;  

/*get local ip addr with default device eth0*/
unsigned long getLocalIp(){
    int inet_sock=socket(AF_INET, SOCK_DGRAM, 0); 
    struct ifreq ifr;  
	char my_ip_addr[32]={NULL};  
    strcpy(ifr.ifr_name, "eth0");  
    ioctl(inet_sock, SIOCGIFADDR, &ifr);  
    strcpy(my_ip_addr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));  
    unsigned long src_ip_addr = 0;
    src_ip_addr = inet_addr(my_ip_addr);
    return src_ip_addr;
}


static void timer(){
    exit(0);
}

/*TCP伪首部pseudo header*/  
struct psd_hdr  
{  
    unsigned long src_addr; //src addr     4B
    unsigned long des_addr; //des addr     4B
    char zero;       //                                        1B
    char ptcl; //协议类型                            1B  
    unsigned short length; //length        2B 
};  //sum                                 12Bytes
  
/*TCP header */
/**/
struct _tcphdr  
{  
    unsigned short tcph_srcport; //src port                                   16bits
    unsigned short tcph_desport; //des port                                   16bits
    unsigned int tcph_seq; //seq                                                       32bits
    unsigned int tcph_ack; //ack_seq                                              32bits
    //为了方便，将首部长度 保留字 flag分为4+4+8
    unsigned char tcph_length;//                                                        8bits
    unsigned char tcph_flag; //flag                                                8bits       URG  ACK  PSH  RST  SYN  FIN
    unsigned short tcph_win; //window                                           16bits
    unsigned short tcph_sum; //checksum                                       16bits
    unsigned short tcph_urp; // urg_ptr                                        16bits
};   //sum                                                   20Bytes     
  
/* CRC 16 checksum */  
unsigned short checksum(unsigned short *data,int length){
	register int left = length;
	register unsigned short * word = data;
	register int sum = 0;
	unsigned short ret = 0;
	while (left >1){
		sum += *word++;
		left -= 2;
	}
	if(left ==1){
		*(unsigned char *)(&ret) = *(unsigned char *) word;
		sum +=ret;
 	}
 	sum = (sum>>16) + (sum & 0xffff);
 	sum += (sum>>16);
 	ret = ~sum;
 	return (ret);
}


/*TCP syn SEND PACKAGE*/
/*flag is 2   0x00010 -->SYN =1*/
/*argv1 port,argv2 flag*/
void send_syn(int port,unsigned char flag){  
        //设置目标端口  
        target.sin_port = htons(port) ;  
        //create tcp package 
        char buffer[256] ;  
        memset(buffer,0,256) ;  
        struct _tcphdr tcpHeader ;  
        struct psd_hdr psdHeader ;  
        //填充TCP  package
        tcpHeader.tcph_desport = htons(port) ;  
        tcpHeader.tcph_srcport = htons(6666) ;  
        tcpHeader.tcph_seq = htonl(0x1245678);  
        tcpHeader.tcph_ack = 0;  
        tcpHeader.tcph_length = (sizeof(tcpHeader) / 4 << 4 | 0);  
        tcpHeader.tcph_flag = flag ;
        tcpHeader.tcph_win = htons(16384) ;  
        tcpHeader.tcph_urp = 0;  
        tcpHeader.tcph_sum = 0;  
        //TCP伪首部
        psdHeader.src_addr = myaddr.sin_addr.s_addr;  //src address
        psdHeader.des_addr = target.sin_addr.s_addr;  //des address
        psdHeader.zero = 0;  // 0
        psdHeader.ptcl = IPPROTO_TCP ;  //协议类型
        psdHeader.length = htons(sizeof(tcpHeader)) ;  //length
        //set checksum 
        memcpy(buffer,&psdHeader,sizeof(psdHeader)) ;  
        memcpy(buffer+sizeof(psdHeader),&tcpHeader,sizeof(tcpHeader)) ;  
        tcpHeader.tcph_sum = checksum((unsigned short*)buffer,sizeof(psdHeader)+sizeof(tcpHeader)) ;  
        //TCP+IP
        memcpy(buffer,&tcpHeader,sizeof(tcpHeader)) ;  
        int ret = sendto(sock,buffer,sizeof(tcpHeader),0,(struct sockaddr*)&target,sizeof(target)) ;  
        if(ret == -1){  
            printf("send error!:%s\n",strerror(errno)) ;  
            exit(-1);  
        }
}  

/*recv tcp package*/
void* recv_pack(){  
    //接收的过程recvfrom  
    struct _tcphdr* tcph ;
    //存放package  
    char msg[1024] ;  
    int len = sizeof(myaddr);  
    int size;  
    alarm(30);//alarm 30s   exit after 30s
    while(1){  
        //msg set zero
        memset(msg,0,1024) ;  
        //接收返回包 放入msg
        size = recvfrom(sock,msg,sizeof(msg),0,(struct sockaddr*)&myaddr,&len) ;  
        if (size == -1) break ;  
        //IP头部第一个字段的+ip header size  , 指针指向tcp header
        tcph = (struct _tcphdr*)(msg + 20) ;  
        if (size < (20 + 20)){/*读出的数据小于两个头的最小长度的话continue*/  
            continue;  
        }  
        //check port 
        if(ntohs(tcph->tcph_desport) != 6666){  
            continue ;  
        }  
        //check flag 
        //端口开放,ACK +SYN,flag is 0x010010   
        if(tcph->tcph_flag == 18){  
            //flag =4 0x000100   回复RST包
            send_syn(ntohs(tcph->tcph_srcport),4) ;  
            printf("%d\t端口开放\n",ntohs(tcph->tcph_srcport)) ;  
            continue ;  
        }  
        //端口未开放 发送ACK+RST,flag is 0x010100      
        if(tcph->tcph_flag == 20){  
            //printf("%d 端口未开放\n",ntohs(tcph->tcph_srcport)) ;  
            continue ;  
        }
    }  
}  

 
int main(int argc,char* argv[]){  
    if(argc!=2){
        printf("Required root.\n");
        printf("Usage: %s  ipaddress \n",argv[0]);
        return 0;
    }
        //signal alarm
    signal(SIGALRM, timer);
    //set target ip address
    target.sin_family = AF_INET ;  
    //set target ip
    inet_pton(AF_INET,argv[1],&target.sin_addr);
    //set my ip address
    myaddr.sin_family = AF_INET ;  
    /*set recv port*/
    myaddr.sin_port = htons(6666) ;  
    myaddr.sin_addr.s_addr = getLocalIp();
    //raw socket,use tcp protocol 
    sock = socket(AF_INET,SOCK_RAW,IPPROTO_TCP) ;  
    if(sock == -1){  
        printf("socket error:%s\n",strerror(errno)) ;  
        exit(-1) ;  
    }  
    int i ;
    pthread_create(&thread,NULL,recv_pack,NULL) ; 
    for(i=1;i<65535;i++){  
        send_syn(i,2);  //flag =2  -->  0x00010 -->SYN =1
    }
    pthread_join(thread,NULL) ;  
    close(sock) ;  
    return 0 ;  
}  
  
 

