/*ping.c*/
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#define ICMP_ECHOREPLY 0
#define ICMP_ECHO 8

typedef struct pingm_packet{
    struct timeval tv_begin;//发送时间
    struct timeval tv_end;//接收时间
    short seq;//序列号
    int flag;//是否收到回应报，1 for no
}pingm_packet;

//创建了128个pingm_packet结构
static pingm_packet pingpacket[128];
//寻找对应的icmp包
static pingm_packet *icmp_findpacket(int seq);
//CRC 16校验和计算程序
static unsigned short icmp_cksum(unsigned char *data, int len);
//时间差
static struct timeval icmp_tvsub(struct timeval end,struct timeval begin);
static void icmp_statistics(void);
static void icmp_pack(struct icmp *icmph, int seq,struct timeval *tv,int length);
static int icmp_unpack(char *buf ,int len);
static void *icmp_send(void *argv);
static void *icmp_recv(void *argv);
static void icmp_sigint(int signo);
static void icmp_usage();
#define K 1024
#define BUFFERSIZE 72
//发送缓冲区大小
static unsigned char send_buff[BUFFERSIZE];
//接收缓冲区大小
static unsigned char recv_buff[2*K];
static struct sockaddr_in dest;//目的主机地址
static int rawsock=0 ;//发送接收线程的socket描述符
static pid_t pid=0;//进程id 后面用来判断是否是本进程的数据包
static int alive=0;
static short packet_send=0;
static short packet_recv=0;
static char dest_str[80];//目标主机字符串 
static struct timeval tv_begin,tv_end,tv_interval;//时间结构

//用法提示函数
static void icmp_usage(){
    printf("ping aaa.bbb.ccc.ddd\n");
}

/**
 *
 * main
 * 
 **/
int main(int argc ,char *argv[]){
    struct hostent *host=NULL;
    struct protoent *protocol=NULL;
    char protoname[]="icmp";
    unsigned long inaddr=1;
    int size = 128* K;
    if(argc<2){
        icmp_usage();
        return -1;
    }
    //获取ICMP协议类型对应的值
    protocol = getprotobyname(protoname);
    if(protocol==NULL){
        perror("getprotobyname()");
        return -1;
    }

    memcpy(dest_str,argv[1],strlen(argv[1])+1);
    //将预分配的包空间置零
    memset(pingpacket,0,sizeof(pingm_packet)*128);
    //设置套接字为原始套接字，并提供协议类型
    rawsock = socket(AF_INET,SOCK_RAW,protocol->p_proto);
    if(rawsock<0){
        perror("socket");
        return -1;
    }
    //设置进程ID
    pid=getuid();

    //setsockopt设置套接字选项，SOL_SOCKET通用套接字类型，SO_RCVBUF接收缓冲区大小,后两个参数为值和值的长度
    setsockopt(rawsock,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size));

    //套接字数据结构,用来赋值，先全0覆盖
    bzero(&dest,sizeof(dest));
    //套接字的domain
    dest.sin_family=AF_INET;
    
    //输入的目的地址
    inaddr=inet_addr(argv[1]);

    if(inaddr==INADDR_NONE){
        //无效的IP
        host=gethostbyname(argv[1]);
        if(host==NULL){
            perror("gethostbyname");
            return -1;
        }
        memcpy((char *)&dest.sin_addr,host->h_addr,host->h_length);
    }
    else{
        memcpy((char *)&dest.sin_addr,&inaddr,sizeof(inaddr));
    }
    inaddr = dest.sin_addr.s_addr;
    //打印信息
    printf("PING %s (%ld.%ld.%ld.%ld) 56(84)bytes of data.\n",dest_str,(inaddr&0x000000FF)>>0,(inaddr&0x0000FF00)>>8,(inaddr&0x00FF0000)>>16,(inaddr&0xFF000000)>>24);
    //挂载信号
    signal(SIGINT,icmp_sigint);

    //设置发送、接收标志
    alive=1;
    //创建发送与接收线程句柄
    pthread_t send_id,recv_id;
    int err=0;
    err=pthread_create(&send_id,NULL,icmp_send,NULL);//创建发送线程，绑定icmp_send函数
    if(err<0){
        return -1;
    }

    //创建接收线程，绑定函数icmp_recv
    err=pthread_create(&recv_id,NULL,icmp_recv,NULL);
    if(err<0){
        return -1;
    }

    //等待线程结束
    pthread_join(send_id,NULL);
    pthread_join(recv_id,NULL);

    //关闭套接字
    close(rawsock);
    icmp_statistics();
    return 0;
}

/**CRC16 checksum icmp_cksum
 * @param: data,
 *         len
 * return value:
 *        result(type short)
 */
static unsigned short icmp_cksum(unsigned char *data,int len){
    int sum=0;
    int odd=len & 0x01;//得到长度奇偶性
    /**
     * 处理掉前面的偶数个字节
     */
    while(len & 0xfffe){
        sum += *(unsigned short *)data;
        data += 2;
        len -= 2;
    }
    /*处理最后一个字节*/
    if(odd){
        unsigned short tmp = ((*data)<<8) & 0xff00;
        sum += tmp;
    }
    sum = (sum>>16) + (sum & 0xffff);//高位与低位相加
    sum += (sum>>16);//溢出位相加
    return ~sum;//取反
}


/**
 *seq =-1 查找空包
 * 否则查找seq对应包
 *  
 */
static pingm_packet *icmp_findpacket(int seq){
    int i=0;
    pingm_packet *found =NULL;
    if (seq==-1){
        for (i=0;i<128;i++){
            //根据设置的flag进行查找
            if(pingpacket[i].flag==0){
                found=&pingpacket[i];
                break;
            }
        }
    }
    else if(seq>=0){
        //根据seq值进行查找对应于seq的发送包
        for (i=0;i<128;i++){
            if(pingpacket[i].seq==seq){
                found=&pingpacket[i];
                break;
            }
        }
    }
    return found;
}

/**
 * 計算時間差
 */
static struct timeval icmp_tvsub(struct timeval end,struct timeval begin){
    struct timeval tv;
    tv.tv_sec=end.tv_sec - begin.tv_sec;
    tv.tv_usec = end.tv_usec - begin.tv_usec;
    //当毫秒数小于0
    if(tv.tv_usec<0){
        tv.tv_sec--;
        tv.tv_usec+=1000000;
    }
    return tv;
} 


//icmp数据包打包函数
static void icmp_pack(struct icmp *icmph, int seq,struct timeval *tv,int length){
    unsigned char i = 0;
    icmph->icmp_type = ICMP_ECHO;//类型为ECHO
    icmph->icmp_code = 0;//code 为0
    icmph->icmp_cksum = 0;//校验和初始为0
    icmph->icmp_seq = seq;//seq值
    icmph->icmp_id = pid & 0xffff;//填入进程id值，返回时根据id值得到对应的进程
    for (i=0;i<length;i++)
        icmph->icmp_data[i]=i;
    //算校验和
    icmph->icmp_cksum = icmp_cksum((unsigned char *)icmph,length);
}

//解icmp包，打印信息
static int icmp_unpack(char * buf,int len){
    int i,iphdrlen;
    struct ip *ip = NULL;
    struct icmp * icmp=NULL;
    int rtt;

    ip=(struct ip*)buf;
    iphdrlen=(ip->ip_hl)*4;
    //指针移至首部后开始
    icmp=(struct icmp*)(buf+iphdrlen);
    len -=iphdrlen;
    //判断长度
    if(len<8){
        printf("ICMP packets\'s length is less than 8\n");
        return -1;
    }
    //判断是否为ECHOREPLY类型返回包，以及进程id是否对应本进程
    if((icmp->icmp_type==ICMP_ECHOREPLY) && (icmp->icmp_id == pid) ){
        struct timeval tv_internel,tv_recv,tv_send;
        //前往发送包池查找对应seq的包
        pingm_packet* packet =icmp_findpacket(icmp->icmp_seq);
        if (packet==NULL){
            return -1;
        }
        //标志对应的发送包已收到其返回包
        packet->flag = 0;
        tv_send=packet->tv_begin;
        gettimeofday(&tv_recv,NULL);
        //计算时间差得到往返时间
        tv_internel=icmp_tvsub(tv_recv,tv_send);
        rtt=tv_internel.tv_sec*1000+tv_internel.tv_usec/1000;
        //打印发送包和返回包里的时间差
        printf("%d bytes from %s: icmp_seq=%u ttl=%d rtt=%d ms\n",len,inet_ntoa(ip->ip_src),icmp->icmp_seq,ip->ip_ttl,rtt);
        packet_recv++;
    }
    else{
        return -1;
    }
}


// 发送ICMP ECHO包
static void* icmp_send(void *argv){
    gettimeofday(&tv_begin,NULL);
    while(alive){
        int size=0;
        struct timeval tv;
        gettimeofday(&tv,NULL);
        //寻找一个空包位置
        pingm_packet *packet =icmp_findpacket(-1);
        if(packet){
            packet->seq=packet_send;
            packet->flag=1;
            gettimeofday(&packet->tv_begin,NULL);
        }
        //icmp包填充
        icmp_pack((struct icmp*)send_buff,packet_send,&tv,64);
        //调用sendto向指定地址发送数据包
        size = sendto(rawsock,send_buff,64,0,(struct sockaddr*)&dest,sizeof(dest));
        if(size<0){
            perror("sendto error");
            continue;
        }
        packet_send++;
        //设置时间间隔每一秒发送一个包
        sleep(1);
    }
}

// 接受ping目的主机的回复
static void *icmp_recv(void * argv){
    struct timeval tv;
    tv.tv_sec=0;
    tv.tv_usec=200;
    fd_set readfd;
    while(alive){
        int ret = 0;
        FD_ZERO(&readfd);
        FD_SET(rawsock,&readfd);
        //设置select函数的轮询时间为200us
        ret=select(rawsock+1,&readfd,NULL,NULL,&tv);
        switch(ret){
            case -1:
            // 发生错误
                break;
            case 0:
            // 超时
                break;
            default:
                {
                    int fromlen=0;
                    struct sockaddr from;
                    //接收数据包
                    int size = recv(rawsock,recv_buff,sizeof(recv_buff),0);
                    if(errno==EINTR){
                        perror("recvfrom error");
                        continue;
                    }
                    //解包
                    ret=icmp_unpack(recv_buff,size);
                    if(ret==-1){
                        continue;
                    }
                }
                break;
        }
    }
}

/**
 * SIGINT信号处理函数
 */
static void icmp_sigint(int signo){
    //设置alive为0 停止
    alive=0;
    gettimeofday(&tv_end,NULL);
    tv_interval = icmp_tvsub(tv_end,tv_begin);
    return;
}

/**
 *统计打印ICMP的发送接收结果 
 */
static void icmp_statistics(void){
    long time = (tv_interval.tv_sec*1000) + (tv_interval.tv_usec/1000);
    printf("--- %s ping statistics ---\n",dest_str);
    //发送时间数、接收时间数、丢失百分比、时间
    printf("%d packets transmitted, %d received, %d%c packet loss, time %ld ms\n",packet_send,packet_recv,(packet_send-packet_recv)*100/packet_send,'%',time);
}
