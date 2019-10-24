#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <errno.h>
#include <time.h>

#define NF_DROP 0
#define NF_ACCEPT 1




typedef enum
{
	none=0,fix,valid
} csum_mode;

struct cbdata_s
{
	bool debug;
	csum_mode csum;
	int qnum;
	uint8_t ipp_xor;
	uint32_t data_xor;
	size_t data_xor_offset,data_xor_len;
};

struct cbdata_s cbdata;


bool proto_check_ipv4(uint8_t *data,size_t len)
{
	return 	len>=20 && (data[0] & 0xF0)==0x40 &&
		len>=((data[0] & 0x0F)<<2);
}
// move to transport protocol
void proto_skip_ipv4(uint8_t **data,size_t *len)
{
	size_t l;
	
	l = (**data & 0x0F)<<2;
	*data += l;
	*len -= l;
}

bool proto_check_ipv6(uint8_t *data,size_t len)
{
	return 	len>=40 && (data[0] & 0xF0)==0x60 &&
		(len-40)>=htons(*(uint16_t*)(data+4)); // payload length
}
void proto_skip_ipv6_base_header(uint8_t **data,size_t *len)
{
	*data += 40; *len -= 40; // skip ipv6 base header
}


static uint16_t ip4_checksum(const struct iphdr *iphdr)
{
	const uint16_t *w = (uint16_t*)iphdr;
	uint8_t len = iphdr->ihl<<2;
	uint32_t sum=0;

	while (len > 1)
	{
		sum += *w++;
        	len -= 2;
	}
	if ( len & 1 )
	{
		// Add the padding if the packet lenght is odd
		uint16_t v=0;
		*(uint8_t *)&v = *((uint8_t *)w);
		sum += v;
	}
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return (uint16_t)(~sum);
}
void ip4_fix_checksum(struct iphdr *ip)
{
	ip->check = 0;
	ip->check = ip4_checksum(ip);
}


uint16_t tcpudp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr, uint8_t protocol)
{
	const uint16_t *buf=buff;
	uint16_t *ip_src=(uint16_t *)&src_addr, *ip_dst=(uint16_t *)&dest_addr;
	uint32_t sum;
	size_t length=len;

	// Calculate the sum
	sum = 0;
	while (len > 1)
	{
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}
	if ( len & 1 )
	{
		// Add the padding if the packet lenght is odd
		uint16_t v=0;
		*(uint8_t *)&v = *((uint8_t *)buf);
		sum += v;
	}
		
	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(protocol);
	sum += htons(length);
	
	// Add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum
	return (uint16_t)(~sum);
}
uint16_t tcpudp6_checksum(const void *buff, int len, const struct in6_addr *src_addr, const struct in6_addr *dest_addr, uint8_t protocol)
{
	const uint16_t *buf=buff;
	const uint16_t *ip_src=(uint16_t *)src_addr, *ip_dst=(uint16_t *)dest_addr;
	uint32_t sum;
	int length=len;
	
	// Calculate the sum
	sum = 0;
	while (len > 1)
	{
		sum += *buf++;
		if (sum & 0x80000000)
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}
	if ( len & 1 )
	{
		// Add the padding if the packet lenght is odd
		uint16_t v=0;
		*(uint8_t *)&v = *((uint8_t *)buf);
		sum += v;
	}
	
	// Add the pseudo-header
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *(ip_src++);
	sum += *ip_src;
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *(ip_dst++);
	sum += *ip_dst;
	sum += htons(protocol);
	sum += htons(length);
	
	// Add the carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	// Return the one's complement of sum
	return (uint16_t)(~sum);
}



void fix_transport_checksum(struct iphdr *ip,struct ip6_hdr *ip6, uint8_t *tdata,size_t tlen)
{
	uint8_t proto;
	uint16_t check,check_old;

	if (!!ip==!!ip6) return; // must be only one

	proto = ip ? ip->protocol : ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	switch(proto)
	{
		case IPPROTO_TCP :
			if (tlen<sizeof(struct tcphdr)) return;
			check_old = ((struct tcphdr*)tdata)->check;
			((struct tcphdr*)tdata)->check = 0;
			break;
		case IPPROTO_UDP:
			if (tlen<sizeof(struct udphdr)) return;
			check_old = ((struct udphdr*)tdata)->check;
			((struct udphdr*)tdata)->check = 0;
			break;
		default:
			return;
	}
	check = ip ? tcpudp_checksum(tdata, tlen, ip->saddr, ip->daddr, proto) : tcpudp6_checksum(tdata, tlen, &ip6->ip6_src, &ip6->ip6_dst, proto);
	switch(proto)
	{
		case IPPROTO_TCP:
			((struct tcphdr*)tdata)->check = check;
			break;
		case IPPROTO_UDP:
			((struct udphdr*)tdata)->check = check;
			break;
	}
	if (cbdata.debug) printf("fix_transport_checksum pver=%c proto=%u %04X => %04X\n",ip ? '4' : '6',proto,check_old,check);

}

uint32_t rotl32 (uint32_t value, unsigned int count)
{
    return value << count | value >> (32 - count);
}
#if defined (__GNUC__) && (defined (__x86_64__) || defined (__i386__))
// sse can cause crashes if unaligned
__attribute__ ((target("no-sse")))
#endif
void modify_packet_payload(struct iphdr *ip,struct ip6_hdr *ip6, uint8_t *tdata,size_t tlen, int indev, int outdev)
{
	if (tlen>cbdata.data_xor_offset)
	{
		uint8_t *data = tdata;
		size_t len = tlen;

		if (cbdata.debug) printf("modify_packet_payload data_xor %08X\n",cbdata.data_xor);

		len-=cbdata.data_xor_offset;
		data+=cbdata.data_xor_offset;
		if (cbdata.data_xor_len < len) len = cbdata.data_xor_len;
		uint32_t xor = htonl(cbdata.data_xor);
		for( ; len>=4 ; len-=4,data+=4) *(uint32_t*)data ^= xor;
		xor = cbdata.data_xor;
		while(len--) *data++ ^= (unsigned char)(xor=rotl32(xor,8));

		// incoming packets : we cant just disable sum check. instead we forcibly make checksum valid
		// if indev==0 it means packet was locally generated. no need to fix checksum because its supposed to be valid
		if (cbdata.csum==valid || cbdata.csum==fix && indev) fix_transport_checksum(ip,ip6,tdata,tlen);
	}
}

bool modify_ip4_packet(uint8_t *data,size_t len, int indev, int outdev)
{
	bool bRes=false;
	struct iphdr *iphdr = (struct iphdr*)data;

	if (cbdata.data_xor)
	{
		uint8_t *tdata=data;
		size_t tlen=len;
		proto_skip_ipv4(&tdata,&tlen);
		modify_packet_payload(iphdr,NULL,tdata,tlen, indev,outdev);
		bRes=true;
	}
	if (cbdata.ipp_xor)
	{
		uint8_t proto = iphdr->protocol;
		iphdr->protocol ^= cbdata.ipp_xor;
		if (cbdata.debug) printf("modify_ipv4_packet proto %u=>%u\n",proto,iphdr->protocol);
		ip4_fix_checksum(iphdr);
		bRes=true;
	}
	return bRes;
}
bool modify_ip6_packet(uint8_t *data,size_t len, int indev, int outdev)
{
	bool bRes=false;
	struct ip6_hdr *ip6hdr = (struct ip6_hdr*)data;

	if (cbdata.data_xor)
	{
		uint8_t *tdata=data;
		size_t tlen=len;
		proto_skip_ipv6_base_header(&tdata,&tlen);
		modify_packet_payload(NULL,ip6hdr,tdata,tlen, indev,outdev);
		bRes=true;
	}
	if (cbdata.ipp_xor)
	{
		uint8_t proto = ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt ^= cbdata.ipp_xor;
		if (cbdata.debug) printf("modify_ipv6_packet proto %u=>%u\n",proto,ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt);
		bRes=true;
	}
	return bRes;
}


typedef enum
{
	pass=0,modify,drop
} packet_process_result;
packet_process_result processPacketData(uint8_t *data_pkt,size_t len_pkt, int indev, int outdev)
{
	struct iphdr *iphdr = NULL;
	struct ip6_hdr *ip6hdr = NULL;
	bool bMod=false;

	if (proto_check_ipv4(data_pkt,len_pkt))
		bMod = modify_ip4_packet(data_pkt,len_pkt, indev,outdev);
	else if (proto_check_ipv6(data_pkt,len_pkt))
		bMod = modify_ip6_packet(data_pkt,len_pkt, indev,outdev);
	return bMod ? modify : pass;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *cookie)
{
	__be32 id;
	size_t len;
	struct nfqnl_msg_packet_hdr *ph;
	uint8_t *data;

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ph ? ntohl(ph->packet_id) : 0;

	len = nfq_get_payload(nfa, &data);
	if (cbdata.debug) printf("packet: id=%d len=%zu\n",id,len);
	if (len >= 0)
	{
		switch(processPacketData(data, len, nfq_get_indev(nfa), nfq_get_outdev(nfa)))
		{
			case modify : return nfq_set_verdict(qh, id, NF_ACCEPT, len, data);
			case drop : return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}
	}

	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

bool setpcap(cap_value_t *caps,int ncaps)
{
	cap_t capabilities;
	
	if (!(capabilities = cap_init()))
		return false;
	
	if (ncaps && (cap_set_flag(capabilities, CAP_PERMITTED, ncaps, caps, CAP_SET) ||
		cap_set_flag(capabilities, CAP_EFFECTIVE, ncaps, caps, CAP_SET)))
	{
		cap_free(capabilities);
		return false;
	}
	if (cap_set_proc(capabilities))
	{
		cap_free(capabilities);
		return false;
	}
	cap_free(capabilities);
	return true;
}
int getmaxcap()
{
	int maxcap = CAP_LAST_CAP;
	FILE *F = fopen("/proc/sys/kernel/cap_last_cap","r");
	if (F)
	{
		int n=fscanf(F,"%d",&maxcap);
		fclose(F);
	}
	return maxcap;
	
}
bool dropcaps()
{
	// must have CAP_SETPCAP at the end. its required to clear bounding set
	cap_value_t cap_values[] = {CAP_NET_ADMIN,CAP_SETPCAP};
	int capct=sizeof(cap_values)/sizeof(*cap_values);
	int maxcap = getmaxcap();

	if (setpcap(cap_values, capct))
	{
		for(int cap=0;cap<=maxcap;cap++)
		{
			if (cap_drop_bound(cap))
			{
				fprintf(stderr,"could not drop cap %d\n",cap);
				perror("cap_drop_bound");
			}
		}
	}
	// now without CAP_SETPCAP
	if (!setpcap(cap_values, capct - 1))
	{
		perror("setpcap");
		return false;
	}
	return true;
}
bool droproot(uid_t uid, gid_t gid)
{
	if (uid || gid)
	{
		if (prctl(PR_SET_KEEPCAPS, 1L))
		{
			perror("prctl(PR_SET_KEEPCAPS): ");
			return false;
		}
		if (setgid(gid))
		{
			perror("setgid: ");
			return false;
		}
		if (setuid(uid))
		{
			perror("setuid: ");
			return false;
		}
	}
	return dropcaps();
}

void daemonize()
{
	int pid;

	pid = fork();
	if (pid == -1)
	{
		perror("fork: ");
		exit(2);
	}
	else if (pid != 0)
		exit(0);

	if (setsid() == -1)
		exit(2);
	if (chdir("/") == -1)
		exit(2);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	/* redirect fd's 0,1,2 to /dev/null */
	open("/dev/null", O_RDWR);
	int fd;
	/* stdin */
	fd=dup(0);
	/* stdout */
	fd=dup(0);
	/* stderror */
}

bool writepid(const char *filename)
{
	FILE *F;
	if (!(F=fopen(filename,"w")))
		return false;
	fprintf(F,"%d",getpid());
	fclose(F);
	return true;
}


void exithelp()
{
	printf(
	" --qnum=<nfqueue_number>\n"
	" --daemon\t\t\t; daemonize\n"
	" --pidfile=<filename>\t\t; write pid to file\n"
	" --user=<username>\t\t; drop root privs\n"
	" --debug\t\t\t; print debug info\n"
	" --uid=uid[:gid]\t\t; drop root privs\n"
	" --ipproto-xor=0..255|0x00-0xFF\t; xor protocol ID with given value\n"
	" --data-xor=0xDEADBEAF\t\t; xor IP payload (after IP header) with 32-bit HEX value\n"
	" --data-xor-offset=<position>\t; start xoring at specified position after IP header end\n"
	" --data-xor-len=<bytes>\t\t; xor block max length. xor entire packet after offset if not specified\n"
	" --csum=none|fix|valid\t\t; transport header checksum : none = dont touch, fix = ignore checksum on incoming packets, valid = always make checksum valid\n"
	);
	exit(1);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	int option_index=0;
	int v;
	bool daemon=false;
	uid_t uid=0;
	gid_t gid=0;
	char pidfile[256];

	srand(time(NULL));

	memset(&cbdata,0,sizeof(cbdata));
	cbdata.data_xor_len=0xFFFF;
	*pidfile = 0;

	const struct option long_options[] = {
		{"qnum",required_argument,0,0},	// optidx=0
		{"daemon",no_argument,0,0},		// optidx=1
		{"pidfile",required_argument,0,0},	// optidx=2
		{"user",required_argument,0,0 },// optidx=3
		{"uid",required_argument,0,0 },// optidx=4
		{"debug",no_argument,0,0 },// optidx=5
		{"ipproto-xor",required_argument,0,0},	// optidx=6
		{"data-xor",required_argument,0,0},	// optidx=7
		{"data-xor-offset",required_argument,0,0},	// optidx=8
		{"data-xor-len",required_argument,0,0},	// optidx=9
		{"csum",required_argument,0,0},	// optidx=10
		{NULL,0,NULL,0}
	};
	if (argc<2) exithelp();
	while ((v=getopt_long_only(argc,argv,"",long_options,&option_index))!=-1)
	{
	    if (v) exithelp();
	    switch(option_index)
	    {
		case 0: /* qnum */
		    cbdata.qnum=atoi(optarg);
		    if (cbdata.qnum<0 || cbdata.qnum>65535)
		    {
			fprintf(stderr,"bad qnum\n");
			exit(1);
		    }
		    break;
		case 1: /* daemon */
		    daemon = true;
		    break;
		case 2: /* pidfile */
		    strncpy(pidfile,optarg,sizeof(pidfile));
		    pidfile[sizeof(pidfile)-1]='\0';
		    break;
		case 3: /* user */
	    	{
	    		struct passwd *pwd = getpwnam(optarg);
			if (!pwd)
			{
				fprintf(stderr,"non-existent username supplied\n");
				exit(1);
			}
			uid = pwd->pw_uid;
			gid = pwd->pw_gid;
			break;
	    	}
		case 4: /* uid */
			gid=0x7FFFFFFF; // default git. drop gid=0
			if (!sscanf(optarg,"%u:%u",&uid,&gid))
			{
				fprintf(stderr, "--uid should be : uid[:gid]\n");
				exit(1);
			}
			break;
		case 5: /* debug */
			cbdata.debug = true;
			break;
		case 6: /* ipproto-xor */
			{
				uint u;
				if (!sscanf(optarg,"0x%X",&u) && !sscanf(optarg,"%u",&u) || u>255)
				{
					fprintf(stderr, "ipp-xor should be 1-byte decimal or 0x<HEX>\n");
					exit(1);
				}
				cbdata.ipp_xor = (uint8_t)u;
			}
			break;
		case 7: /* data-xor */
			if (!sscanf(optarg,"0x%X",&cbdata.data_xor))
			{
				fprintf(stderr, "data-xor should be 32 bit HEX starting with 0x\n");
				exit(1);
			}
			break;
		case 8: /* data-xor-offset */
			cbdata.data_xor_offset = (size_t)atoi(optarg);
			break;
		case 9: /* data-xor-len */
			cbdata.data_xor_len = (size_t)atoi(optarg);
			break;
		case 10: /* csum */
			if (!strcmp(optarg,"none"))
				cbdata.csum=none;
			else if (!strcmp(optarg,"fix"))
				cbdata.csum=fix;
			else if (!strcmp(optarg,"valid"))
				cbdata.csum=valid;
			else
			{
				fprintf(stderr, "invalid csum parameter\n");
				exit(1);
			}
			break;
	    }
	}

	if (daemon) daemonize();
	
	h = NULL;
	qh = NULL;

	if (*pidfile && !writepid(pidfile))
	{
		fprintf(stderr,"could not write pidfile\n");
		goto exiterr;
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		goto exiterr;
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		goto exiterr;
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		goto exiterr;
	}

	printf("binding this socket to queue '%u'\n", cbdata.qnum);
	qh = nfq_create_queue(h, cbdata.qnum, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		goto exiterr;
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		goto exiterr;
	}
	
	if (!droproot(uid,gid)) goto exiterr;
	fprintf(stderr,"Running as UID=%u GID=%u\n",getuid(),getgid());
		
	fd = nfq_fd(h);
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
	{
	    int r=nfq_handle_packet(h, buf, rv);
	    if (r) fprintf(stderr,"nfq_handle_packet error %d\n",r);
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	return 0;
	
exiterr:
	if (qh) nfq_destroy_queue(qh);
	if (h) nfq_close(h);
	return 1;
}
