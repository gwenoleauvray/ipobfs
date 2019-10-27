#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ip6_checksum.h>

MODULE_DESCRIPTION("ip obfuscator. xor ip protocol or data payload with some values. supports multiple profiles triggered by fwmark bits");
MODULE_AUTHOR("bol-van");
MODULE_LICENSE("GPL");

static bool debug=false;

#define MAX_MARK	32

static uint mark[MAX_MARK], markmask=0;
static int ct_mark=0;
static uint data_xor[MAX_MARK];
static int ct_data_xor=0;
static uint data_xor_offset[MAX_MARK];
static int ct_data_xor_offset=0;
static uint data_xor_len[MAX_MARK];
static int ct_data_xor_len=0;
static ushort ipp_xor[MAX_MARK];
static int ct_ipp_xor=0;
static char *pre="mangle";
static char *csum="none";

module_param(debug,bool,0640);
MODULE_PARM_DESC(debug, "printk debug info");
module_param_array(mark,uint,&ct_mark,0640);
MODULE_PARM_DESC(mark, "fwmark filters : 0x100,0x200,0x400. if markmask not specified, markmask=mark for each profile");
module_param(markmask,uint,0640);
MODULE_PARM_DESC(markmask, "fwmark filter mask : common mask for all profiles. if not specified, markmask=mark for each profile");
module_param_array(data_xor,uint,&ct_data_xor,0640);
MODULE_PARM_DESC(data_xor, "uint32 data xor : 0xDEADBEAF,0x01020304,0");
module_param_array(data_xor_offset,uint,&ct_data_xor_offset,0640);
MODULE_PARM_DESC(data_xor_offset, "start xoring from position : 4,4,8");
module_param_array(data_xor_len,uint,&ct_data_xor_len,0640);
MODULE_PARM_DESC(data_xor_len, "xor no more than : 0,0,16");
module_param_array(ipp_xor,ushort,&ct_ipp_xor,0640);
MODULE_PARM_DESC(ipp_xor, "xor ip protocol with : 0,0x80,42");
module_param(pre,charp,0000);
MODULE_PARM_DESC(pre, "prerouting hook priority : mangle or raw");
module_param(csum,charp,0000);
MODULE_PARM_DESC(debug, "csum mode : none=invalid csums are ok, fix = valid csums on original outgoing packets, valid = valid csums on obfuscated outgoing packets");

#define GET_PARAM(name,idx) (idx<ct_##name ? name[idx] : 0)

typedef enum
{
	none=0,fix,valid
} t_csum_mode;
static t_csum_mode csum_mode;

static int find_mark(uint fwmark)
{
	int i;
	if (markmask)
	{
		uint m = fwmark & markmask;
		for(i=0;i<ct_mark;i++)
			if (m == mark[i]) return i;
	}
	else
	{
		for(i=0;i<ct_mark;i++)
			if (fwmark & mark[i]) return i;
	}
	return -1;
}


static void ip4_fix_checksum(struct iphdr *ip)
{
	ip->check = 0;
	ip->check = ip_fast_csum(ip,ip->ihl);
}



static void fix_transport_checksum(struct sk_buff *skb)
{
	uint tlen;
	u8 *pn, *pt, pver, proto;
	__sum16 check=0, check_old;

	if (!skb_transport_header_was_set(skb)) return;

	pn = skb_network_header(skb);
	pver = (*pn)>>4;

	switch(pver)
	{
		case 4:
			proto = ((struct iphdr*)pn)->protocol;
			break;
		case 6:
			proto = ((struct ipv6hdr*)pn)->nexthdr;
			break;
		default:
			return;
	}
	pt = skb_transport_header(skb);
	tlen = skb_headlen(skb) - (skb->transport_header - skb->network_header);
	switch(proto)
	{
		case IPPROTO_TCP :
			check_old = ((struct tcphdr*)pt)->check;
			((struct tcphdr*)pt)->check = 0;
			break;
		case IPPROTO_UDP:
			check_old = ((struct udphdr*)pt)->check;
			((struct udphdr*)pt)->check = 0;
			break;
		default:
			return;
	}
	switch(pver)
	{
		case 4:
			check = csum_tcpudp_magic(((struct iphdr*)pn)->saddr, ((struct iphdr*)pn)->daddr, tlen, proto, csum_partial(pt, tlen, 0));
			break;
		case 6:
			check = csum_ipv6_magic(&((struct ipv6hdr*)pn)->saddr, &((struct ipv6hdr*)pn)->daddr, tlen, proto, csum_partial(pt, tlen, 0));
			break;
	}
	switch(proto)
	{
		case IPPROTO_TCP:
			((struct tcphdr*)pt)->check = check;
			break;
		case IPPROTO_UDP:
			((struct udphdr*)pt)->check = check;
			break;
	}
	if (debug) printk(KERN_DEBUG "ipobfs: fix_transport_checksum pver=%u proto=%u %04X => %04X\n",pver,proto,check_old,check);
}



static u32 rotr32 (u32 value, uint count)
{
	return value >> count | value << (32 - count);
}
static u32 rotl32 (u32 value, uint count)
{
	return value << count | value >> (32 - count);
}
// this function can xor multi-chunked payload. data point to a chunk, len means chunk length, data_pos tells byte offset of this chunk
static void modify_packet_payload(u8 *data,uint len,uint data_pos, uint data_xor, uint data_xor_offset, uint data_xor_len)
{
	if (!data_xor_len) data_xor_len=0xFFFF;
	if (data_xor_offset<(data_pos+len) && (data_xor_offset+data_xor_len)>data_pos)
	{
		uint start=data_xor_offset>data_pos ? data_xor_offset-data_pos : 0;
		if (start<len)
		{
			uint end = ((data_xor_offset+data_xor_len)<(data_pos+len)) ? data_xor_offset+data_xor_len-data_pos : len;
			u32 xor,nxor,n;
			len = end-start;
			data += start;
			xor = data_xor;
			nxor = htonl(xor);
			n = (4-((data_pos+start)&3))&3;
			if (n)
			{
				xor=rotr32(xor,(n-1)<<3);
				while(n && len) *data++ ^= (u8)xor, len--, n--, xor=rotl32(xor,8);
			}
			for( ; len>=4 ; len-=4,data+=4) *(u32*)data ^= nxor;
			xor = data_xor;
			while(len--) *data++ ^= (u8)(xor=rotl32(xor,8));
		}
	}
}
static void modify_skb_payload(struct sk_buff *skb,int idx,bool bOutgoing)
{
	uint len;
	u8 *p;

	if (!skb_transport_header_was_set(skb)) return;

	len = skb_headlen(skb);
	p = skb_transport_header(skb);
	len -= skb->transport_header - skb->network_header;

	// dont linearize if possible
	if (skb_is_nonlinear(skb))
	{
		uint last_mod_offset=GET_PARAM(data_xor_offset,idx)+GET_PARAM(data_xor_len,idx);
		if(last_mod_offset>len)
		{
			if (debug) printk(KERN_DEBUG "ipobfs: nonlinear skb. skb_headlen=%u skb_data_len=%u skb_len_transport=%u last_mod_offset=%u. linearize skb",skb_headlen(skb),skb->data_len,len,last_mod_offset);
			if (skb_linearize(skb)) 
			{
				if (debug) printk(KERN_DEBUG "ipobfs: failed to linearize skb");
				return;
			}
			len = skb_headlen(skb);
			p = skb_transport_header(skb);
			len -= skb->transport_header - skb->network_header;
		}
		else
			if (debug) printk(KERN_DEBUG "ipobfs: nonlinear skb. skb_headlen=%u skb_data_len=%u skb_len_transport=%u last_mod_offset=%u. dont linearize skb",skb_headlen(skb),skb->data_len,len,last_mod_offset);
	}

	if (bOutgoing && csum_mode==fix) fix_transport_checksum(skb);
	modify_packet_payload(p,len,0, GET_PARAM(data_xor,idx), GET_PARAM(data_xor_offset,idx), GET_PARAM(data_xor_len,idx));
	if (csum_mode==valid) fix_transport_checksum(skb);

	if (debug) printk(KERN_DEBUG "ipobfs: modify_skb_payload proto=%u len=%u\n",skb->protocol,len);
}

static uint hook_ip4(void *priv, struct sk_buff *skb, const struct nf_hook_state *state,bool bOutgoing)
{
	int idx = find_mark(skb->mark);
	if (idx!=-1)
	{
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		if (GET_PARAM(data_xor,idx)) modify_skb_payload(skb,idx,bOutgoing);
		if (GET_PARAM(ipp_xor,idx))
		{
			struct iphdr *ip = ip_hdr(skb);
			u8 proto = ip->protocol;
			ip->protocol ^= (u8)GET_PARAM(ipp_xor,idx);
			ip4_fix_checksum(ip);
			if (debug) printk(KERN_DEBUG "ipobfs: modify_ipv4_packet proto %u=>%u\n",proto,ip->protocol);
		}
	}
	return NF_ACCEPT;
}
static uint hook_ip6(void *priv, struct sk_buff *skb, const struct nf_hook_state *state,bool bOutgoing)
{
	int idx = find_mark(skb->mark);
	if (idx!=-1)
	{
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		if (GET_PARAM(data_xor,idx)) modify_skb_payload(skb,idx,bOutgoing);
		if (GET_PARAM(ipp_xor,idx))
		{
			struct ipv6hdr *ip6 = ipv6_hdr(skb);
			u8 proto = ip6->nexthdr;
			ip6->nexthdr ^= (u8)GET_PARAM(ipp_xor,idx);
			if (debug) printk(KERN_DEBUG "ipobfs : modify_ipv6_packet proto %u=>%u\n",proto,ip6->nexthdr);
		}
	}
	return NF_ACCEPT;
}

static uint hook_ip4_pre(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return hook_ip4(priv,skb,state,false);
}
static uint hook_ip4_post(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return hook_ip4(priv,skb,state,true);
}
static uint hook_ip6_pre(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return hook_ip6(priv,skb,state,false);
}
static uint hook_ip6_post(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	return hook_ip6(priv,skb,state,true);
}
static struct nf_hook_ops nfhk[4] =
{
	{.hook=hook_ip4_pre, .hooknum=NF_INET_PRE_ROUTING, .pf=PF_INET, .priority=NF_IP_PRI_MANGLE-1},
	{.hook=hook_ip4_post, .hooknum=NF_INET_POST_ROUTING, .pf=PF_INET, .priority=NF_IP_PRI_MANGLE+1},
	{.hook=hook_ip6_pre, .hooknum=NF_INET_PRE_ROUTING, .pf=PF_INET6, .priority=NF_IP_PRI_MANGLE+1},
	{.hook=hook_ip6_post, .hooknum=NF_INET_POST_ROUTING, .pf=PF_INET6, .priority=NF_IP_PRI_MANGLE+1}
};

static int nf_priority_from_string(char *s)
{
	int pri = NF_IP_PRI_MANGLE;
	if (s && !strcmp(s,"raw")) pri=NF_IP_PRI_RAW;
	return pri;
}
 
int init_module()
{
	int i,priority_pre;

	if (!strcmp(csum,"fix")) csum_mode = fix;
	else if (!strcmp(csum,"valid")) csum_mode = valid;
	else csum_mode = none;

	printk(KERN_INFO "ipobfs: module loaded : debug=%d pre=%s csum=%s ct_mark=%d markmask=%08X ct_ipp_xor=%d ct_data_xor=%d ct_data_xor_offset=%d\n",
		debug,pre,
		csum_mode==fix ? "fix" : csum_mode==valid ? "valid" : "none",
		ct_mark,markmask,ct_ipp_xor,ct_data_xor,ct_data_xor_offset);
	for (i=0;i<ct_mark;i++) printk(KERN_INFO "ipobfs: mark 0x%08X/0x%08X : ipp_xor=%u(0x%02X) data_xor=0x%08X data_xor_offset=%u data_xor_len=%u\n",
		GET_PARAM(mark,i),markmask ? markmask : GET_PARAM(mark,i),
		GET_PARAM(ipp_xor,i),GET_PARAM(ipp_xor,i),GET_PARAM(data_xor,i),GET_PARAM(data_xor_offset,i),GET_PARAM(data_xor_len,i));

	priority_pre=nf_priority_from_string(pre)+1;
	for(i=0;i<(sizeof(nfhk)/sizeof(*nfhk));i++)
		if (nfhk[i].hooknum==NF_INET_PRE_ROUTING) nfhk[i].priority=priority_pre;
	nf_register_net_hooks(&init_net, nfhk, sizeof(nfhk)/sizeof(*nfhk));

	return 0;
}
 
void cleanup_module()
{
	nf_unregister_net_hooks(&init_net,nfhk, sizeof(nfhk)/sizeof(*nfhk));
	printk(KERN_INFO "ipobfs: module unloaded\n");
}
