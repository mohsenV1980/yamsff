/*-
 * Copyright (c) 2015 Henning Matyschok
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. 
 */
#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_mpls.h"
#include "opt_mpls_debug.h"

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_llc.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/if_llatbl.h>
#include <net/route.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netmpls/mpls.h>

extern struct ifaddr * 	mpls_ifawithseg_fib(struct sockaddr *, 
	u_int, int);
extern struct ifaddr * 	mpls_ifaof_ifpforseg(struct sockaddr *, 
	struct ifnet *, int);
struct ifaddr * 	mpls_ifawithdst_fib(struct sockaddr *, int, u_int, int);
struct ifaddr * 	mpls_ifaof_ifpfordst(struct sockaddr *, int, 
	struct ifnet *, int);
extern struct ifaddr * 	mpls_ifaof_ifpforxconnect(struct sockaddr *, 
	struct sockaddr *, struct ifnet *, int);
extern struct ifaddr * 	mpls_ifawithxconnect_fib(struct sockaddr *, 
	struct sockaddr *, u_int, int);

/*
 * Accessor macros for rtinfo{} SPI.
 */
#define	rti_dst(_rti) 	((_rti)->rti_info[RTAX_DST])
#define	rti_gateway(_rti) 	((_rti)->rti_info[RTAX_GATEWAY])
#define	rti_netmask(_rti) 	((_rti)->rti_info[RTAX_NETMASK])
#define	rti_ifaaddr(_rti) 	((_rti)->rti_info[RTAX_IFA])
#define	rti_ifpaddr(_rti) 	((_rti)->rti_info[RTAX_IFP])
#define	rti_brd(_rti) 	((_rti)->rti_info[RTAX_BRD])
#define	rti_flags(_rti) 	((_rti)->rti_flags)
#define rti_ifa(_rti) 	((_rti)->rti_ifa)
#define rti_ifp(_rti) 	((_rti)->rti_ifp)

/*
 * Radix-trie containing (free) generated ilm.
 */

SYSCTL_DECL(_net_mpls);

static int mpls_rtq_max_routes = 2048;

SYSCTL_INT(_net_mpls, OID_AUTO, rtmaxcache, CTLFLAG_RW,
	&mpls_rtq_max_routes, 0,
	"Upper limit on dynamically learned routes");
/*
 * Debugging hooks.
 */

static struct radix_node *
mpls_rn_delroute(void *v_arg, void *netmask_arg, struct radix_node_head *head)
{	

	return (rn_delete(v_arg, netmask_arg, head));
}

static struct radix_node *
mpls_rn_addroute(void *v_arg, void *n_arg, struct radix_node_head *head,
	    struct radix_node *treenodes)
{
	
	return (rn_addroute(v_arg, n_arg, head, treenodes));
}

static struct radix_node *
mpls_rn_lookup(void *v_arg, void *m_arg, struct radix_node_head *head)
{
	
	return (rn_lookup(v_arg, m_arg, head));
}

static struct radix_node *
mpls_rn_match(void *v_arg, struct radix_node_head *rnh)
{

	return (rn_match(v_arg, rnh));
}

/*
 * Removes incoming-label map (ilm).
 */
static void	
mpls_rn_clsroute(struct radix_node *rn, struct radix_node_head *rnh)
{
	struct rtentry *rt = (struct rtentry *)rn;
	
	KASSERT((rnh != NULL), ("radix_node_head{} not defined"));
	KASSERT((rt != NULL), ("ilm not defined"));
	
	RT_LOCK_ASSERT(rt);

	if ((rt->rt_flags & RTF_UP) 
		&& (rt->rt_refcnt < 1)) 
			rtexpunge(rt);
}
int	mpls_rn_inithead(void **, int);

/*
 * Initialize tree.
 */
int
mpls_rn_inithead(void **rnh0, int off)
{
	int error;
	struct radix_node_head *rnh;
	
	if ((error = rn_inithead(rnh0, off)) != 0) {
		rnh = *rnh0;
		
		rnh->rnh_close = mpls_rn_clsroute;
		rnh->rnh_deladdr = mpls_rn_delroute;
		rnh->rnh_matchaddr = mpls_rn_match;

		rnh->rnh_addaddr = mpls_rn_addroute;
		rnh->rnh_lookup = mpls_rn_lookup;	
	}
	return (error);
}
 
/*
 * X-connect.
 */

int 	mpls_rt_output_fib(struct rt_msghdr *, struct rt_addrinfo *, 
	struct rtentry **, u_int);


/*
 * Accept by socket(4) in AF_ROUTE or by mpls_control received 
 * service requests.
 *
 *  o RTAX_DST holds key x for fec = < x, nh > where nh -> ifp
 *
 *  o RTAX_GATEWAY holds by sockaddr_ftn{} for MPLS label
 *    binding necessary < seg_i , seg_j > tuple where seg_i 
 *    denotes key for by nhlfe generated ilm, Furthermore,
 *    seg_j denotes typically upstream label for transmission
 *    downstream by interface ifp in link-layer. 
 *  
 *  o In rt_addrinfo{} spi contained flags encodes with MPLS 
 *    label binding linked operation.
 *   
 *    RTF_[POP|PUSH|SWAP] - self expanatory.
 *
 *    RTF_MPE denotes that by fec generated nhlfe encodes 
 *    by seg_j initial label of Label Switch Path (lsp) in 
 *    data plane.
 *
 *    RTF_LLDATA denotes that nhlfe is linked to an interface 
 *    in link-layer where targeted interface represents fec by 
 *    nhlfe itself. RTF_LLDATA occours combined with RTF_MPE.
 *
 *  o RTF_STK, denotes label stacking, but not yet fully
 *    implemented.
 *
 * XXX; under construction.
 */
int
mpls_rt_output_fib(struct rt_msghdr *rtm, struct rt_addrinfo *rti, 
		struct rtentry **rt, u_int fibnum)
{ 		
	struct mpls_ailiasreq ifra;
	int error, fmsk, omask, cmd;
	
#ifdef MPLS_DEBUG
	(void)printf("%s\n", __func__);
#endif /* MPLS_DEBUG */

	bzero(&ifra, sizeof(ifra));

	switch ((int)rtm->rtm_type) {
	case RTM_ADD:	
/*
 * Apply MPLS label binding on Forward Equivalence Class (fec).
 */		
		cmd = SIOCSIFADDR;
		break;		
	case RTM_DELETE:
/*
 * Delete MPLS label binding on fec.
 */
		cmd = SIOCDIFADDR;
		break;
	case RTM_GET:  	
/*
 * Fetch Incoming Label Map (ilm) by MPLS label binding on fec.
 */	
		cmd = SIOCGIFADDR;
		break;
	default:
		log(LOG_INFO, "%s: command invalid\n", __func__);		
		error = EOPNOTSUPP;
		goto out;
	} 
	omsk = RTF_MPLS_OMASK;
	fmsk = RTF_MPLS;
/*
 * Determine, if MPLS label binding is possible.
 */	
	if ((fmsk = (rti_flags(rti) & fmsk)) == 0)  {
		log(LOG_INFO, "%s: requested route not "
			"in AF_MPLS domain", __func__);
		error = EINVAL;
		goto out;
	}
	fmsk |= (rti_flags(rti) & RTF_GATEWAY) ? RTF_GATEWAY : RTF_LLDATA;
	
	if ((fmsk = (rti_flags(rti) & fmsk)) == 0)  {
		log(LOG_INFO, "%s: flags invalid\n", __func__);
		error = EINVAL;
		goto out;
	}
	fmsk |= (rti_flags(rti) & omsk);

	switch (fmsk & omsk) {
	case RTF_POP:
	case RTF_PUSH: 	/* FALLTRHOUGH */
	case RTF_SWAP:
		break;
	default:	
		log(LOG_INFO, "%s: opcode invalid\n", __func__);		
		error = EINVAL;
		goto out;
	}
	fmsk |= (rti_flags(rti) & RTF_STK) ? RTF_STK : RTF_MPE;	
	ifra.ifra_flags = (rti_flags(rti) & fmsk);

	if ((error = mpls_sa_validate(rti_gateway(rti), AF_MPLS)) != 0) {
		log(LOG_INFO, "%s: segment invalid\n", __func__);
		goto out;	
	} 
	bcopy(rti_gateway(rti), &ifra.ifra_seg, rti_gateway(rti)->sa_len);
	
	if ((error = mpls_sa_validate(rti_dst(rti), AF_UNSPEC)) != 0) {
		log(LOG_INFO, "%s: dst in fec invalid\n", __func__);
		goto out;	
	}
	bcopy(rti_dst(rti), &ifra.ifra_x, rti_dst(rti)->sa_len);	  	
/*
 * Perform MPLS control operations on interface-layer.
 */
	error = mpls_control(NULL, cmd, (void *)&ifra, NULL, NULL);
	
	if (cmd  == SIOCGIFADDR) {
/*
 * Fetch ilm, if fec does not denote ingress route by lsp_in.
 */		
		if ((ifra.ifra_flags & RTF_MPE) == 0) 
			*rt = rtalloc1_fib(seg, 0, 0UL, fibnum);	
		
		error = (*rt == NULL) ? EADDRNOTAVAIL : error;	
	}
out:	
	return (error);
}
#undef rti_dst
#undef rti_gateway
#undef rti_netmask
#undef rti_ifaaddr
#undef rti_ifpaddr
#undef rti_brd
#undef rti_flags
#undef rti_ifa
