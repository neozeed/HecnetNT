extern unsigned char buffer[2000];
extern unsigned char wbuffer[2000];
extern int buffersize;
extern int wbuffercount;
extern int buffercount;


//This build enables compression.  This breaks operation with 'normal' HECnet.
//But things like doom get 80% compression so it's not nescicarly a bad thing.
//But you can mix cbridges & normal bridges


/* A simple DECnet bridge program
 * (c) 2003, 2005 by Johnny Billquist
 * Version 2.3 Bugfix. Ports are *unsigned* shorts...
 *             Also added -Wall, and cleaned up some warnings.
 * Version 2.2 Some cleanup, bugfixes and general improvements.
 * Version 2.1 Fixed code for OpenBSD and FreeBSD as well.
 * Version 2.0 (I had to start using a version number sometime, and
 *              since I don't have any clue to the history of my
 *              development here, I just picked 2.0 because I liked
 *              it.)
 * Some more text will come here later.
 */

#define DEBUG 1
//#define DEBUG2

#ifndef DPORT
#define DPORT 0			/* Set to some other value for a default */
#endif

#define MAX_HOST 16

#define CONF_FILE "bridge.conf"

#include <stdio.h>
#include <stdlib.h>

#ifdef UNIX
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#ifdef linux
#include <pcap-bpf.h>
#else
#include <net/bpf.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <pcap.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#else
#include "wingetopt.h"
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <conio.h>
#include "../pcap/pcap.h"

typedef unsigned int in_addr_t;		//This isn't in windows...
#define bzero(d,n) memset(d,0,n)	//neither is this.
//externs
inet_aton(const char *cp, struct in_addr *addr);
void usleep(int waitTime);
#endif

void NOexit(int rc);				//I wanted to capture the exit's.

/* Throttling control:
 * THROTTLETIME - (mS)
 *                If packets come closer in time than this, they are
 *                a base for perhaps considering throttling.
 * THROTTLEPKT  - (#)
 *                The number of packets in sequence that fulfill
 *                THROTTLETIME that means throttling will kick in.
 * THROTTLEDELAY - (uS)
 *                The delay to insert when throttling is active.
 *
 * Passive connection control:
 * PASSIVE_TMO - (mS)
 *               If nothing has been received from a passive node
 *               in this time, sending to it will stop.
 */

#define THROTTLETIME 5
#define THROTTLEPKT 4
#define THROTTLEDELAY 10000

#define PASSIVE_TMO 180000L

#define THROTTLEMASK ((1 << THROTTLEPKT) - 1)

typedef enum {HECUnknown, DECnet, LAT, IPX, TCPIP, APPLETALK, MAXTYP} pkttyp;

#define ETHERTYPE_DECnet 0x6003
#define ETHERTYPE_LAT 0x6004
#define ETHERTYPE_MOPDL 0x6001
#define ETHERTYPE_MOPRC 0x6002
#define ETHERTYPE_LOOPBACK 0x9000
#define ETHERTYPE_IPXNEW        0x8037  /* IPX (Novell Netware?) */
#define ETHERTYPE_IPX           0x8137  /* Novell (old) NetWare IPX (ECONFIG E option) */
#define ETHERTYPE_NOVELL        0x8138  /* Novell, Inc. */
#define ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#define ETHERTYPE_REVARP   0x8035
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define ETHERTYPE_ATALK		0x809b


/*from cisco
Ethernet Version II
Cisco: ipx encapsulation arpa
Novell: Ethernet_II
IPX-over-Ethernet II frames have an Ethernet type/length field value of
0x8137 (which is a type value).
 

Cisco: ipx encapsulation novell-ether
Novell: Ethernet_802.3 (old-style default Novell encapsulation, versions 2.x through 3.11)

Cisco: ipx encapsulation sap (prior to Cisco IOS ver. 10.0: Novell encapsulation iso1)
Novell: Ethernet_802.2 (new-style default Novell encapsulation, versions > 3.11)

Cisco: ipx encapsulation snap
Novell: Ethernet_snap

*/


#define MAX(a,b) (a>b?a:b)

/* This is a very simple and small program for bpf that just
   filters out anything by any protocol that we *know* we're
   not interested in.
 */

/* This captures everything... only for testing!
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
	BPF_STMT(BPF_RET+BPF_K, (UINT)-1)	// Accept. Value is bytes to be
*/

struct bpf_insn insns[] = {
  BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_ATALK, 11, 0),			//Appletalk, untested
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_ARP, 10, 0),			//For TCP/IP... Don't use on a normal LAN!!!
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_REVARP, 9, 0),
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 8, 0),
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_NOVELL, 7, 0),			//Added IPX Ethernet_II support
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IPX, 6, 0),
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_LOOPBACK, 5, 0),
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_MOPRC, 4, 0),
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_MOPDL, 3, 0),
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_LAT, 2, 0),
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_DECnet, 1, 0),
  BPF_STMT(BPF_RET+BPF_K, 0),
  BPF_STMT(BPF_RET+BPF_K, 1518),
};

/* The structures and other global data we keep info in.
   It would perhaps be nice if we could reload this, and
   in case of failure keep the old stuff, but for now we
   don't care that much... */

/* The data structures we have are the port, which describe
   a source/destination for data. It also holds info about which
   kind of traffic should be forwarded to this site. It is also
   used to filter incoming packets. If we don't send something, we
   don't want it from that side either.
   We have the host table, which is a hash table for all known
   destinations, so that we can optimize the traffic a bit.

   When data arrives, we filter, process and send it out again.
 */



struct BRIDGE {
  char name[40];
  char host[80];
  struct in_addr addr;
  unsigned short port;
  int passive;
  int anyport;
  int fd;
  int types[MAXTYP];
  char last[8][14];
  int lastptr;
  int rcount;
  int tcount;
  int xcount;
  struct timeval lasttime;
  int throttle;
  int throttlecount;
  struct timeval lastrcv;
  int compressed;
  pcap_t *pcap;
};

struct DATA {
  int source;
  pkttyp type;
  int len;
  const unsigned char *data;
};

struct HOST {
  struct HOST *next;
  unsigned char mac[6];
  int bridge;
};

#define HOST_HASH 65536

struct HOST *hosts[HOST_HASH];
struct BRIDGE bridge[MAX_HOST];
int bcnt = 0;
unsigned int sd;
char *config_filename;

/* Here come the code... */

/* lookup
   Based on a sockaddr_in, find the corresponding bridge entry.
   Returns the index of the bridge, or -1 if no match. */
int lookup(struct sockaddr_in *sa)
{
  int i;

  for (i=0; i<bcnt; i++) {
    if ((bridge[i].addr.s_addr == sa->sin_addr.s_addr) &&
	((bridge[i].port == sa->sin_port) || bridge[i].anyport)) {
      bridge[i].port = sa->sin_port;
      return i;
    }
  }
  return -1;
}



/* lookup_bridge
   Based on a string, find the corresponding bridge.
   Returns bridge index, or -1 if no match.
*/
int lookup_bridge(char *newbridge)
{
  int i;
  size_t l = strlen(newbridge);
#if DEBUG2
  printf("Trying to match %s\n", newbridge);
#endif
  for (i=0; i<bcnt; i++) {
#if DEBUG2
    printf("Matching against: %s\n", bridge[i].name);
#endif
    if ((strcmp(newbridge,bridge[i].name) == 0) &&
	(l == strlen(bridge[i].name))) {
#if DEBUG2
      printf("Found match: %s == %s\n", newbridge, bridge[i].name);
#endif
      return i;
    }
  }
#if DEBUG
  printf("No match found\n");
#endif
  return -1;
}


/* add_bridge
   Adds a new bridge entry to the list of bridges
*/
void add_bridge(char *name, char *dst, int compressed)
{
  struct hostent *he;
  char rhost[40];
  int port=0;
  int i,found=0;
  in_addr_t addr=0;
  char *p;
  int passive = 0;
  int anyport = 0;

  if (bcnt < MAX_HOST) {
    bzero(&bridge[bcnt],sizeof(struct BRIDGE));
    if (*name == '~') {
      passive = 1;
      name++;
    }
    if (*name == '*') {
      anyport = 1;
      name++;
    }

	bridge[bcnt].compressed = compressed;

    strcpy(bridge[bcnt].name,name);
#ifdef UNIX
    p = index(dst,':');
#else
	p = strchr(dst,':');	//index doesn't exist in win32 space
#endif
    if (p == NULL) {		/* Assume local descriptor */
      struct bpf_program pgm;
      char ebuf[PCAP_ERRBUF_SIZE];

      ebuf[0] = 0;
	  printf("Opening pcap %s\n",dst);
      if ((bridge[bcnt].pcap = pcap_open_live(dst, 1518, 1, 0, ebuf)) == 0) {
	printf("Error opening device.\n%s\n", ebuf);
	NOexit(1);
      }
	  ebuf[0] = 0;
	  //make pcap nonblocking
	  if (pcap_setnonblock(bridge[bcnt].pcap,1,ebuf))
	  {printf("Error going into nonblocking.\n[%s]\n", ebuf);
	NOexit(1);
	  }

	  
      if (ebuf[0]) printf("warning: %s\n", ebuf);

      pgm.bf_len=sizeof(insns)/sizeof(struct bpf_insn);
      pgm.bf_insns=insns;
      if (pcap_setfilter(bridge[bcnt].pcap, &pgm) == -1) {
	pcap_perror(bridge[bcnt].pcap, "loading filter program");
	NOexit(1);
      }

      strcpy(bridge[bcnt].host,dst);
      bridge[bcnt].addr.s_addr = 0;
      bridge[bcnt].port = 0;
      bridge[bcnt].fd = pcap_fileno(bridge[bcnt].pcap);

#if defined(__NetBSD__) || defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__)
      i = 1;
      if (ioctl(bridge[bcnt].fd,BIOCIMMEDIATE,&i) == -1) {
	perror("ioctl");
	NOexit(1);
      }
      if (ioctl(bridge[bcnt].fd,BIOCSHDRCMPLT,&i)) {
	perror("BIOCSHDRCMPLT");
	NOexit(1);
      }
#endif

      found = -1;
    } else {
      *p = ' ';
      sscanf(dst,"%s %d", rhost, &port);
      if ((he = gethostbyname(rhost)) != NULL) {
	addr = *(in_addr_t *)he->h_addr;
	found = -1;
      } else {
	found = inet_aton(rhost,(struct in_addr *)&addr);
      }
      if (found) {
	strcpy(bridge[bcnt].host,rhost);
	bridge[bcnt].addr.s_addr = addr;
	bridge[bcnt].port = htons(port);
	bridge[bcnt].fd = sd;
      }
    }
    if (found) {
      for (i=0; i<MAXTYP; i++) bridge[bcnt].types[i] = 0;

      bridge[bcnt].rcount = 0;
      bridge[bcnt].tcount = 0;
      bridge[bcnt].passive = passive;
      bridge[bcnt].anyport = anyport;

      bcnt++;
#if DEBUG
      printf("Adding router ''%s''. %08x:%d\n", name, addr, port);
#endif
    }
  } else {
    printf("Warning. Bridge table full. Not adding %s (%s)\n", name, dst);
  }
}


/* add_service
   Adds a servie to a named bridge.
   Services are different protocols.
*/
int add_service(char *newbridge, pkttyp type, char *name)
{
  int i;
#if DEBUG2
  printf("Adding %s bridge %s.\n", name, newbridge);
#endif
  if ((i = lookup_bridge(newbridge)) >= 0) {
    if (bridge[i].types[type]++ > 0) {
      printf("%s bridge %s added multiple times.\n", name, newbridge);
    }
    return 1;
  }
  return 0;
}


/* read_conf
   Read the config file
*/
void read_conf(int x)
{
  FILE *f;
  int mode = 0;
  int area,node;
  int line;
  char buf[80];
  char buf1[400],buf2[400];
  int i;

  if ((f = fopen(config_filename,"r")) == NULL) {
    perror("opening bridge.conf");
	NOexit(1);
  }

  for (i=0; i<bcnt; i++) {
    if (bridge[i].fd != sd) close(bridge[i].fd);
  }
  bcnt = 0;

  for (i=0; i<HOST_HASH; i++) {
    struct HOST *h, *n;
    h = hosts[i];
    hosts[i] = NULL;
    while(h) {
      n = h->next;
      free(h);
      h = n;
    }
  }

  line = 0;
  while (!feof(f)) {
    if (fgets(buf,80,f) == NULL) continue;
    buf[strlen(buf)-1] = 0;
    line++;
    if((strlen(buf) > 2) && (buf[0] != '!')) {
      if(buf[0]=='[') {
	mode = -1;
	if(strcmp(buf,"[bridge]") == 0) mode = 0;
	if(strcmp(buf,"[cbridge]") == 0) mode = 1;
	if(strcmp(buf,"[decnet]") == 0) mode = 2;
	if(strcmp(buf,"[lat]") == 0) mode = 3;
	if(sscanf(buf,"[source %d.%d]", &area, &node) == 2) mode = 4;
	if(strcmp(buf,"[relay]") == 0) mode = 5;
	if(strcmp(buf,"[ipx]") == 0) mode = 6;
	if(strcmp(buf,"[tcpip]") == 0) mode = 7;
	if(strcmp(buf,"[appletalk]") == 0) mode = 8;
	if(mode < 0) {
	  printf("Bad configuration at line %d\n%s\n", line,buf);
	  NOexit(1);
	}
      } else {
	switch (mode) {
	case 0:
	  if (sscanf(buf, "%s %s", buf1, buf2) == 2) {
	    add_bridge(buf1,buf2,0);
	  } else {
	    printf("Bad bridge at line %d\n%s\n", line, buf);
		NOexit(1);
	  }
	  break;
	case 1:
	  if (sscanf(buf, "%s %s", buf1, buf2) == 2) {				//This is a compressed bridge type.  Using LZSS
	    add_bridge(buf1,buf2,1);
	  } else {
	    printf("Bad cbridge at line %d\n%s\n", line, buf);
		NOexit(1);
	  }
	  break;
	case 2:
	  if (!add_service(buf,DECnet,"DECnet"))
	    printf("%d: DECnet bridge %s don't exist.\n", line, buf);
	  break;
	case 3:
	  if (!add_service(buf,LAT,"LAT"))
	    printf("%d: LAT bridge %s don't exist.\n", line, buf);
	  break;
	case 4:
	  break;
	case 5:
	  break;
	case 6:
		if (!add_service(buf,IPX,"IPX"))
		    printf("%d: IPX bridge %s don't exist.\n", line, buf);
		break;
	case 7:
		if (!add_service(buf,TCPIP,"TCPIP"))
		    printf("%d: TCP/IP bridge %s don't exist.\n", line, buf);
		break;
	case 8:
		if (!add_service(buf,APPLETALK,"APPLETALK"))
		    printf("%d: AppleTalk bridge %s don't exist.\n", line, buf);
		break;
	default:
	  printf("weird state at line %d\n",line);
	  NOexit(1);
	}
      }
    }
  }
  fclose(f);
}


/* is_ethertype
   Check if an ethernet packet have a specific ethernet type
   Returns true if so
*/
int is_ethertype(struct DATA *d, unsigned short type)
{
  unsigned char x[2];
  x[0] = (type >> 8);
  x[1] = (type & 255);		/* Yuck, but this makes it byte-order safe */
  return ((d->data[13] == x[1]) &&
	  (d->data[12] == x[0]));
}

/* is_decnet
   Returns true if a packet is of type DECnet
*/
int is_decnet(struct DATA *data)
{
  return is_ethertype(data, ETHERTYPE_DECnet);
}

/* is_lat
   Returns true if a packet is of type LAT, any MOP protocol
   or the loopback protocol.
*/
int is_lat(struct DATA *data)
{
  return (is_ethertype(data, ETHERTYPE_LAT) ||
	  is_ethertype(data, ETHERTYPE_MOPDL) ||
	  is_ethertype(data, ETHERTYPE_MOPRC) ||
	  is_ethertype(data, ETHERTYPE_LOOPBACK));
}

int is_ipx(struct DATA *data)
{
return (is_ethertype(data, ETHERTYPE_IPX) ||
	  is_ethertype(data, ETHERTYPE_NOVELL) );
}

int is_tcpip(struct DATA *data)
{
	return (is_ethertype(data, ETHERTYPE_IP) ||
	  is_ethertype(data, ETHERTYPE_ARP) ||
	  is_ethertype(data, ETHERTYPE_REVARP));
}

int is_appletalk(struct DATA *data)
{
	return(is_ethertype(data,ETHERTYPE_ATALK));
}

/* timedelta
   Return the time from a previous timestamp to current time.
*/
unsigned long timedelta(struct timeval old)
{
  struct timeval now;
  unsigned long delta;
  gettimeofday(&now, NULL);
  delta = now.tv_sec - old.tv_sec;
  delta *= 1000;
  delta += ((now.tv_usec - old.tv_usec) / 1000);
  return delta;
}

/* throttle
   Will pause the execution for the THROTTLEDELAYIME if
   the bridge destination have too many packets within
   a short timeframe to trigger the throtteling mechanism.
*/
void throttle(int index)
{
  unsigned long delta;

  delta = timedelta(bridge[index].lasttime);
  bridge[index].throttle <<= 1;
  bridge[index].throttle += (delta < THROTTLETIME ? 1 : 0);

  if ((bridge[index].throttle & THROTTLEMASK) == THROTTLEMASK) {
    bridge[index].throttlecount++;
    usleep(THROTTLEDELAY);
  }
  gettimeofday(&bridge[index].lasttime,NULL);
}

/* active
   Checks if a bridge is active or not.
*/
int active(int index)
{
  if (bridge[index].passive == 0) return 1;
  if (timedelta(bridge[index].lastrcv) < PASSIVE_TMO) return 1;
  return 0;
}

/* send_packet
   Send an ethernet packet to a specific bridge.
*/
void send_packet(int index, struct DATA *d)
{
  struct sockaddr_in sa;

  if (index == d->source) return; /* Avoid loopback of data. */
  if (bridge[index].types[d->type] == 0) return; /* Avoid sending unwanted frames */

  if (active(index)) {
    bridge[index].tcount++;
    throttle(index);
    if (bridge[index].addr.s_addr == 0) {
//		printf("write frame locally\n");
#ifdef UNIX
      write(bridge[index].fd,d->data,d->len); /* Local network. */
#else
		//Unix can write on pcap like a filehandle, Windows needs to call pcap_sendpacket
	pcap_sendpacket(bridge[index].pcap,d->data,d->len);
#endif
    } else {
      sa.sin_family = AF_INET;	/* Remote network. */
      sa.sin_port = bridge[index].port;
      sa.sin_addr.s_addr = bridge[index].addr.s_addr;
	  
  if(bridge[index].compressed==1)		//Is this a cbridge?
  {
	  buffersize=d->len;				//I know.. this should be passed on Encode..
	  memcpy(buffer,d->data,d->len);	//
	  Encode();							//compress the packet
	  

if(wbuffercount<d->len)				//Sometimes compressed packets are larger than raw.  I know crazy
  {									//So I wrap them in Lz, so I know my compressed from RAW.
  unsigned char tpacket[2000];
  tpacket[0]='L';
  tpacket[1]='z';
  memcpy(tpacket+2,wbuffer,wbuffercount);
  	
  if (sendto(bridge[index].fd,tpacket,wbuffercount+2,0,(struct sockaddr *)&sa,sizeof(sa)) == -1)
		perror("sendto");
  }
  else
  {
	//Compression failed, so we send the frame RAW
	if (sendto(bridge[index].fd,d->data,d->len,0,(struct sockaddr *)&sa,sizeof(sa)) == -1)
		perror("sendto");
  }
  }
  else		//this isn't a cbridge, send packets RAW
  {
	  if (sendto(bridge[index].fd,d->data,d->len,0,(struct sockaddr *)&sa,sizeof(sa)) == -1)
		perror("sendto");
  }

    }
    bridge[index].lastptr = (bridge[index].lastptr+1) & 7;
    memcpy(bridge[index].last[bridge[index].lastptr],d->data,14);
  }
}

void register_source(struct DATA *d)
{
  unsigned short hash;
  struct HOST *h;

  hash = *(unsigned short *)(d->data+10);
  h = hosts[hash];
  while (h) {
    if (memcmp(h->mac, d->data+6, 6) == 0) {
      h->bridge = d->source;
#if DEBUG2
      printf("Setting existing hash to bridge %d\n", h->bridge);
#endif
      return;
    }
    h = h->next;
  }
  h = malloc(sizeof(struct HOST));
  h->next = hosts[hash];
  memcpy(h->mac,d->data+6,6);
  h->bridge = d->source;
#if DEBUG
  printf("Adding new hash entry [%02x:%02x:%02x:%02x:%02x:%02x]. Port is %d\n",h->mac[0],h->mac[1],h->mac[2],h->mac[3],h->mac[4],h->mac[5], h->bridge);
#endif
  hosts[hash] = h;
}

int locate_dest(struct DATA *d)
{
  unsigned short hash;
  struct HOST *h;

  if (d->data[0] & 1) return -1; /* Ethernet multicast */

  hash = *(unsigned short *)(d->data+4);
  h = hosts[hash];
  while (h) {
    if (memcmp(h->mac, d->data, 6) == 0) return h->bridge;
    h = h->next;
  }
  return -1;
}

pkttyp classify_packet(struct DATA *d)
{
  if (is_decnet(d)) return DECnet;
  if (is_lat(d)) return LAT;
  if (is_ipx(d)) return IPX;
  if (is_tcpip(d)) return TCPIP;
  if (is_appletalk(d)) return APPLETALK;

  return HECUnknown;
}

void dump_nomatch(struct sockaddr_in *r, struct DATA *d)
{
#if DEBUG2
  printf("Dumped packet from %s (%d).\n", inet_ntoa(r->sin_addr),ntohs(r->sin_port));
#endif
}

void process_packet(struct DATA *d)
{
  int dst;
  int i;

  bridge[d->source].rcount++;
  gettimeofday(&bridge[d->source].lastrcv, NULL);
  for (i=0; i<8; i++) {
    if (memcmp(bridge[d->source].last[i],d->data,14) == 0) {
      return;
    }
  }

  d->type = classify_packet(d);
  if (d->type == HECUnknown) return;
  if (bridge[d->source].types[d->type] == 0) return;

  bridge[d->source].xcount++;

  register_source(d);
  dst = locate_dest(d);
  if (dst == -1) {
    int i;
    for (i=0; i<bcnt; i++) send_packet(i, d);
  } else {
    send_packet(dst, d);
  }
}

void dump_data()
{
  int i;

  printf("Host table:\n");
  for (i=0; i<bcnt; i++)
    printf("%d: %s %s:%d (Rx: %d Tx: %d (Drop rx: %d)) Active: %d Throttle: %d(%03o)\n",
	   i,
	   bridge[i].name,
	   inet_ntoa(bridge[i].addr),
	   ntohs(bridge[i].port),
	   bridge[i].rcount,
	   bridge[i].tcount,
	   bridge[i].rcount - bridge[i].xcount,
	   active(i),
	   bridge[i].throttlecount,
	   bridge[i].throttle & 255);
  printf("Hash of known destinations:\n");
  for (i=0; i<HOST_HASH; i++) {
    struct HOST *h;
    h=hosts[i];
    while (h) {
      printf("%02x%02x%02x%02x%02x%02x -> %d",
	     (unsigned char)h->mac[0],
	     (unsigned char)h->mac[1],
	     (unsigned char)h->mac[2],
	     (unsigned char)h->mac[3],
	     (unsigned char)h->mac[4],
	     (unsigned char)h->mac[5],
	     h->bridge);
      if ((unsigned char)h->mac[0] == 0xaa &&
	  (unsigned char)h->mac[1] == 0x00 &&
	  (unsigned char)h->mac[2] == 0x04 &&
	  (unsigned char)h->mac[3] == 0x00) {
	printf(" (%d.%d)", h->mac[5] >> 2, ((h->mac[5] & 3) << 8) + h->mac[4]);
      }
      printf("\n");
      h = h->next;
    }
  }
}


int main(int argc, char **argv)
{
  struct sockaddr_in sa,rsa;
  int i,hsock,ch;
  fd_set fds;
  socklen_t ilen;
  int port = 0;
  struct DATA d;
  unsigned char buf[8192];
#ifndef UNIX
  int iResult;
  WSADATA wsaData;
#endif

#ifdef UNIX
  signal(SIGHUP, read_conf);
  signal(SIGUSR1, dump_data);
#else
      iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);		//Initalize WinSock
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }

#endif

  config_filename = CONF_FILE;

  while ((ch = getopt(argc, argv, "d:p:h")) != -1) {
    switch (ch) {
    case 'd':
      config_filename=malloc((int) strlen(CONF_FILE) +
			     (int) strlen(optarg) +
			     2);
      sprintf(config_filename,"%s/%s",optarg,CONF_FILE);
      break;
    case ':':
    case 'p':
      printf("d: %s\n", optarg);
      port = atoi(optarg);
      break;
    case '?':
    case 'h':
    default:
      printf("usage: %s [-p <port>] [-d <dir>] [<port>]\n", argv[0]);
	  NOexit(1);
    }
  }

  argc -= optind;
  argv += optind;

  if (argc > 0) {
    if (port) {
      printf("Error: port already set\n");
	  NOexit(1);
    }
    port = atoi(argv[0]);
  }

#if DPORT
  if (port == 0) port = DPORT;
#endif

  if (port == 0) {
    printf("no port given\n");
	NOexit(1);
  }

#if DEBUG
  printf("Config filename: %s\n",config_filename);
#endif

  if ((sd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
    perror("socket");
	NOexit(1);
  }
  //set socket to nonblocking
#ifdef UNIX 
  fcntl(sd,F_SETFL,O_NONBLOCK);
#else
  // Winsock's way of setting the socket to nonblocking
  {
	u_long iMode=1;
	ioctlsocket(sd,FIONBIO,&iMode);
  }
#endif

  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  sa.sin_addr.s_addr = INADDR_ANY;
  if (bind(sd, (struct sockaddr*)&sa, sizeof(sa)) == -1) {
    perror("bind");
	NOexit(1);
  }

  read_conf(0);

#if DEBUG
  dump_data();
#endif

  while(1) {

    FD_ZERO(&fds);
    hsock = 0;
    for (i=0; i<bcnt; i++) {
      FD_SET(bridge[i].fd, &fds);
      if (bridge[i].fd > hsock) hsock = bridge[i].fd;
    }
    if (select(hsock+1,&fds,NULL,NULL,NULL) == -1) {
      //if (errno != EINTR) {
		if (errno == -1 ) {   //should check for ok/wouldblock I think.
	perror("select");
	printf(" %d",errno);
	NOexit(1);
      }
    }

    for (i=0; i<bcnt; i++) {
      if (FD_ISSET(bridge[i].fd,&fds)) {
	d.source = i;
	if (bridge[i].addr.s_addr == 0) {
	  struct pcap_pkthdr h;
	  d.data = pcap_next(bridge[i].pcap, &h);
	  d.len = h.caplen;
	  if (d.data) {
	    process_packet(&d);
	  }
	} else {
	  ilen = sizeof(rsa);
	  /* Read packet from network*/
	  if ((d.len = recvfrom(bridge[i].fd, buf, 1518, 0,
				(struct sockaddr *)&rsa, &ilen)) > 0) {
		d.data=buf;
		d.len=d.len;
//		d.type=classify_packet(&d);

if(bridge[i].compressed==1)
	{
		if( (buf[0]=='L')&&(buf[1]=='z'))	//check for Lz in the headder
		{
			d.len-=2;
			memcpy(buffer,buf+2,d.len);
			buffersize=d.len;					//Trim headder
			Decode();  
			memcpy(buf,wbuffer,wbuffercount);	//Put things where hecnet expects them.
			d.len=wbuffercount;
		}
		
	}
		//else	//Otherwise it must be a packet, right? carry on?
		
	    
	    if ((d.source = lookup(&rsa)) >= 0) {
	      process_packet(&d);
	    } else {
	      dump_nomatch(&rsa,&d);
	    }
	  }
	}
	FD_CLR(bridge[i].fd, &fds);
#ifdef UNIX
	usleep(10);
#else
	Sleep(1);	//if it doesn't sleep it'll peg the CPU.
#endif
      }
    }
  }
  WSACleanup();
}


void NOexit(int rc)
{
	printf("\nPress Enter to exit..");
	getch();
	WSACleanup();
	exit(rc);
}