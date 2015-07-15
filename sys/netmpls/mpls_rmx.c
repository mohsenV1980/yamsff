/*-
 * Copyright (c) 2014, 2015 Henning Matyschok
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
	struct radix_node_head *rnh;
	int error;

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
 
int 	mpls_rtrequest_fib(int cmd, struct ifaddr *, 
	struct rtentry **, u_int);
int		mpls_purgeaddr(struct ifaddr *);
void 	mpls_link_rtrequest(int, struct rtentry *, struct rt_addrinfo *);
int 	mpls_rt_output_fib(struct rt_msghdr *, struct rt_addrinfo *, 
	struct rtentry **, u_int);

/*
 * Wrapper for rtrequest_fib(9), generates 
 * incoming label mapping based on enclosing 
 * nhlfe whose itself depends on existing
 * fec. 
 */
int 	
mpls_rtrequest_fib(int cmd, struct ifaddr *ifa, 
		struct rtentry **ilm, u_int fibnum)
{
#ifdef MPLS_DEBUG
	(void)printf("%s\n", __func__);
#endif /* MPLS_DEBUG */	
	
	if (ifa == NULL) 
		return (ESRCH);

	if ((ifa->ifa_flags & IFA_NHLFE) == 0) 
		return (EADDRNOTAVAIL);
/*
 * An ingress MPLS label binding is not covered by an ilm. 
 */	
	if (mpls_flags(ifa) & (RTF_MPE|RTF_LLINFO))
		return (0);	

	return (rtrequest_fib(cmd, 
		ifa->ifa_addr, 
		ifa->ifa_dstaddr, 
		ifa->ifa_netmask, 
		mpls_flags(ifa), 
		ilm, fibnum));
}

/*
 * Accepts by socket(4) in AF_ROUTE or by mpls_control received
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
 */
int
mpls_rt_output_fib(struct rt_msghdr *rtm, struct rt_addrinfo *rti, 
		struct rtentry **ilm, u_int fibnum)
{ 	
	
	int omsk, fmsk, flags;
	
	struct sockaddr *x;	
	struct sockaddr *seg;
	struct rtentry *fec;
	struct ifnet *ifp;
	struct sockaddr *nh;
	
	uint32_t seg_in, seg_out;

	struct sockaddr_mpls smpls;
	struct sockaddr_ftn sftn;

	struct ifaddr *oifa, *ifa;
	struct mpls_ifaddr *nhlfe;
	
	int error;
	
#ifdef MPLS_DEBUG
	(void)printf("%s\n", __func__);
#endif /* MPLS_DEBUG */

	switch ((int)rtm->rtm_type) {
	case RTM_ADD:			
	case RTM_DELETE:	/* FALLTRHOUGH */
	case RTM_GET:  	

		omsk = RTF_MPLS_OMASK;
		fmsk = RTF_MPLS;
		flags = 0;
		
		fec = NULL;	
		ifp = NULL;
		
		oifa = ifa = NULL;	
		nhlfe = NULL;
		error = 0;	
		break;
	default:
		log(LOG_INFO, "%s: command invalid\n", __func__);		
		error = EOPNOTSUPP;
		goto out;
	}
/*
 * Determine, if MPLS label binding is possible.
 */	
	if ((fmsk = (rti_flags(rti) & fmsk)) == 0)  {
		log(LOG_INFO, "%s: requested route not "
			"in AF_MPLS domain", __func__);
		error = EINVAL;
		goto out1;
	}
	fmsk |= (rti_flags(rti) & RTF_GATEWAY) ? RTF_GATEWAY : RTF_LLDATA;
	
	if ((fmsk = (rti_flags(rti) & fmsk)) == 0)  {
		log(LOG_INFO, "%s: flags invalid\n", __func__);
		error = EINVAL;
		goto out1;
	}
	fmsk |= (rti_flags(rti) & omsk);

	switch (fmsk & omsk) {
	case RTF_POP:
	case RTF_PUSH: 	/* FALLTRHOUGH */
	case RTF_SWAP:
		fmsk |= (rti_flags(rti) & RTF_STK) ? RTF_STK : RTF_MPE;	
		break;
	default:	
		log(LOG_INFO, "%s: opcode invalid\n", __func__);		
		error = EINVAL;
		goto out1;
	}
	flags = (rti_flags(rti) & fmsk);
	
	if ((error = mpls_sa_validate(rti_dst(rti), AF_UNSPEC)) != 0) {
		log(LOG_INFO, "%s: dst in fec invalid\n", __func__);
		goto out1;	
	}
	x = rti_dst(rti); /* x in fec by < x, nh > where ifp */
	
	if ((error = mpls_sa_validate(rti_gateway(rti), AF_MPLS)) != 0) {
		log(LOG_INFO, "%s: segment invalid\n", __func__);
		goto out1;	
	}                    /* seg = < seg_in, seg_out > */
	seg = rti_gateway(rti);
	seg_in = satosmpls_label(seg) & MPLS_LABEL_MASK;
	seg_out = satosmpls_label(seg) & MPLS_LABEL_MASK;

	if ((x->sa_family == AF_LINK)
		&& (flags & RTF_LLDATA)
		&& (flags & RTF_PUSH) 
		&& (flags & RTF_MPE)) {
/*
 * Per-interface MPLS label space.
 */
 		oifa = ifa_ifwithaddr(x);
 		if (oifa == NULL) {	
 			error = EADDRNOTAVAIL;
 			goto out1;
 		}
 		ifp = oifa->ifa_ifp;
		nh = (struct sockaddr *)&smpls;
		
	} else if (((fec = rtalloc1_fib(x, 0, 0UL, fibnum)) != NULL) 		
		&& (fec->rt_gateway != NULL) && (fec->rt_ifp != NULL)
		&& (fec->rt_ifa != NULL) && (fec->rt_flags & RTF_UP)) {
/*
 * MPLS label space scoped by set containing fec.
 */
		ifp = fec->rt_ifp;
		nh = fec->rt_gateway;
		seg_out = satosftn_label(seg) & MPLS_LABEL_MASK;
	} else {
		log(LOG_INFO, "%s: fec invalid\n", __func__);
		error = ESRCH;	
		goto out1;
	}
/*
 * Discard, if invalid MPLS label binding.
 */	
	if (((flags & omsk) == RTF_SWAP) && (seg_in != seg_out)) {
		log(LOG_INFO, "%s: ftn invalid\n", __func__);		
		error = ESRCH;
		goto out1;
	}
	
	if ((ifp->if_flags & IFF_MPLS) == 0) {
		error = ENXIO;
		goto out1;	
	}
/*
 * Generate an extended gateway 
 * address for nhlfe where
 *
 *	  < op, seg_out, rd >
 *
 * from fec inherited adress 
 * extends.
 */			
	bzero(&sftn, sizeof(sftn));
	bcopy(nh, &sftn, nh->sa_len);
	
	sftn.sftn_len = SFTN_LEN;
	sftn.sftn_op = flags & omsk;
	sftn.sftn_label = seg_out;
	sftn.sftn_vprd = seg_out;
	
	nh = (struct sockaddr *)&sftn;
/*
 * Map key (seg_in) for nhlfe and ilm.
 */	
	bzero(&smpls, sizeof(smpls));
	smpls.smpls_len = SMPLS_LEN;
	smpls.smpls_family = AF_MPLS;
	smpls.smpls_label = seg_in;
	
	seg = (struct sockaddr *)&smpls;
/*
 * X-connect.
 */		
	ifa = mpls_ifaof_ifpforxconnect(seg, nh, ifp, 1);
	if (ifa == NULL) 
		ifa = mpls_ifawithxconnect_fib(seg, nh, fibnum, 1);
	
	switch ((int)rtm->rtm_type) {		
	case RTM_ADD:
	
		if (ifa == NULL) {
			if (flags & RTF_PUSH) {
/*
 * Locate nhlfe on fastpath.
 */				
				ifa = mpls_ifaof_ifpfordst(x, flags & omsk, ifp, 1);
				if (ifa == NULL) 
					ifa = mpls_ifawithdst_fib(x, flags & omsk, fibnum, 1);	
			} else {
/*
 * Locate nhlfe on seg.
 */			
				ifa = mpls_ifaof_ifpforseg(seg, ifp, 1);
				if (ifa == NULL) 
					ifa = mpls_ifawithseg_fib(seg, fibnum, 1);	
			}		
		}
			
		if (ifa == NULL) { 
			nhlfe = (struct mpls_ifaddr *)
				malloc(sizeof(*nhlfe), M_IFADDR, 
					M_ZERO|M_NOWAIT);
		
			if (nhlfe != NULL) {			
				ifa = &nhlfe->mia_ifa;
				ifa_init(ifa);				
			} else	
				error = ENOBUFS;
			
		} else if (ifa->ifa_flags & IFA_NHLFE) { 
/*
 * Reinitialize, if possible.
 */										
			if ((mpls_flags(ifa) & RTF_PUSH)
				&& (fec != NULL)) {
				error = EADDRINUSE;
				break;
			}	
			error = mpls_purgeaddr(ifa);
			nhlfe = (error == 0) ? ifatomia(ifa) : NULL;	
		} else 
			error = EADDRNOTAVAIL;
		
		if (nhlfe == NULL)
			break;	
	
		ifa->ifa_addr = (struct sockaddr *)&nhlfe->mia_seg;
		ifa->ifa_dstaddr = (struct sockaddr *)&nhlfe->mia_nh;	
		ifa->ifa_netmask = (struct sockaddr *)&nhlfe->mia_seg;
		ifa->ifa_ifp = ifp;	
		ifa->ifa_flags |= IFA_NHLFE;
		ifa->ifa_metric = ifp->if_metric;
		
		nhlfe->mia_flags = flags;	
/*
 * Copy key (seg_in).
 */ 		
 		bcopy(seg, ifa->ifa_addr, smpls.smpls_len);			
/*
 * Copy modefied (seg_out) gateway address,
 */		
		bcopy(nh, ifa->ifa_dstaddr, sftn.sftn_len);	
/*
 * Copy key for destination (x) in fec.
 */
		bcopy(x, (struct sockaddr *)&nhlfe->mia_x, x->sa_len);		
/*
 * Enqueue and append nhlfe at link-level address on interface.
 */	
		ifa_ref(ifa);

		NHLFE_WLOCK();
		TAILQ_INSERT_TAIL(&mpls_iflist, ifatomia(ifa), mia_link);	
		NHLFE_WUNLOCK();

		ifa_ref(ifa);

		IF_ADDR_WLOCK(ifp);
		TAILQ_INSERT_AFTER(&ifp->if_addrhead, ifp->if_addr, ifa, ifa_link);
		IF_ADDR_WUNLOCK(ifp);			
/*
 * Create llentry{} by SIOCSIFADDR triggered inclusion mapping.
 */		
		error = (*ifp->if_ioctl)(ifp, SIOCSIFADDR, (void *)ifa);
		if (error != 0) {
			(void)mpls_purgeaddr(ifa);	
			break;
		}
		
		if (mpls_flags(ifa) & RTF_LLDATA) {	
			ifa_ref(ifa);
/*
 * Bind interface, if MPLS label binding was 
 * caused by SIOC[AS]IFADDR control operation.
 */		
			IF_AFDATA_WLOCK(ifp);
			MPLS_IFINFO_IFA(ifp) = ifa;
			ifp->if_flags |= IFF_MPE;	
			IF_AFDATA_WUNLOCK(ifp);	
		}	
/*
 * Generate incoming label map, if necessary.
 */			
		error = mpls_rtrequest_fib((int)rtm->rtm_type, ifa, ilm, fibnum);
		if (error != 0) {
			(void)mpls_purgeaddr(ifa);	
			break;
		}

		if (fec != NULL) {
			fec->rt_ifa->ifa_rtrequest = mpls_link_rtrequest;
/*
 * Fastpath into MPLS transit will be applied on fec, when 
 * MPLS label binding states initial label (lsp_in) on Label 
 * Switch Path (lsp). 
 *
 * The gateway address on by fec implementing rtentry(9) 
 * is replaced with those where is stored by fec (free) 
 * generated nhlfe.
 *  
 * On creation, the nhlfe inherites a modefied version from 
 * original gateway address where maps to enclosing fec. 
 *
 *      + rt_key              .       + MPLS label (BoS)
 *     |                      .       |
 *     v                      .       v
 *   +-------------+----------+-----+------+------+
 *   | 192.168.3.6 | 10.6.1.6 | Op  | 666  | VPRD |
 *   +-------------+----------+-----+------+------+
 *                   A
 *                   |
 *                   + rt_gateway
 *
 * Thus, when fastpath enters the game, by nhlfe extended 
 * gateway address is re-mapped to gateway address on by
 * nhlfe enclosing fec itself.
 *
 * This avoids a second routing table lookup by service 
 * providing MPLS layer, when handoff by protocol-layer
 * processed message primitives (mpi) into MPLS data 
 * plane was performed. 
 *
 * Because by service requesting protocol-layer performed
 * routing decision led to a rtentry(9) with an extended 
 * gateway address (see above), where is therefore accepted 
 * as argument by mpls_output.
 */			
			if ((flags & RTF_MPE) && (flags & RTF_STK)) 
				fec->rt_flags |= RTF_STK;
			else if (flags & RTF_MPE) {			
				error = rt_setgate(fec, rt_key(fec), ifa->ifa_dstaddr);
				if (error != 0) {
					(void)mpls_purgeaddr(ifa);	
					break;
				}
				fec->rt_mtu -= MPLS_HDRLEN; 
				fec->rt_flags |= RTF_MPE;
 			}
 		}	
 		ifa->ifa_flags |= IFA_ROUTE;
	
		if (*ilm != NULL) {
			RT_LOCK(*ilm); 	
			RT_ADDREF(*ilm);
 		} 
 		break;	
	case RTM_DELETE:	
/*
 * Release x-connect.
 */	
		if (ifa == NULL) {
			error = EADDRNOTAVAIL;
			break;
		}
	
		if (fec != NULL) {
			if (mpls_flags(ifa) & RTF_MPE) {
				ssize_t len;

				if (fec->rt_flags & RTF_STK) 
					fec->rt_flags &= ~RTF_STK;
				else if (fec->rt_flags & RTF_MPE) {
/*
 * Restore gateway address, if fec by lsp_in.
 */		
 					bzero(&sftn, sizeof(sftn));
 					nh = (struct sockaddr *)&sftn;	
 				
 					if (fec->rt_flags & RTF_GATEWAY) 
						len = rt_key(fec)->sa_len;
					else	
						len = sizeof(struct sockaddr_dl);
				
					bcopy(ifa->ifa_dstaddr, nh, len);  
					nh->sa_len = len;	
			
					error = rt_setgate(fec, rt_key(fec), nh);
					if (error != 0)
						break;
				
					fec->rt_mtu += MPLS_HDRLEN;
					fec->rt_flags &= ~RTF_MPE;
				}
			}	
		}	
		error = mpls_purgeaddr(ifa);	
		break;
	case RTM_GET:
/*
 * Fetch ilm.
 */	
		if (ifa == NULL) {
			error = EADDRNOTAVAIL;
			break;
		}
		
		if ((flags & RTF_MPE) == 0) 
			*ilm = rtalloc1_fib(seg, 0, 0UL, fibnum);	

		error = (*ilm == NULL) ? EADDRNOTAVAIL : error;	
		break;		
	default: /* NOT REACHEED */
		error = EOPNOTSUPP;	
		break;
	}
out1:	
	if (fec != NULL) 
		RTFREE_LOCKED(fec);

	if (oifa != NULL)
		ifa_free(oifa);

	if (ifa != NULL)
		ifa_free(ifa);	
out:		
	return (error);
}

/*
 * Purge x-connect.
 */
int	
mpls_purgeaddr(struct ifaddr *ifa)
{
	struct ifnet *ifp;
	int error;
	struct sockaddr_mpls smpls;
	struct sockaddr *seg;

#ifdef MPLS_DEBUG
	(void)printf("%s\n", __func__);
#endif /* MPLS_DEBUG */
	
	if (ifa == NULL)
		return (ESRCH);
		
	if ((ifa->ifa_flags & IFA_NHLFE) == 0)
		return (EADDRNOTAVAIL);		
		
	if ((ifp = ifa->ifa_ifp) == NULL) 
		return (EADDRNOTAVAIL);
/*
 * Remove by nhlfe enclosed ilm, if any.
 */		
 	error = mpls_rtrequest_fib((int)RTM_DELETE, ifa, NULL, ifp->if_fib);	
	
	switch (error) {
	case EADDRINUSE: 
		goto out;
	default:
		error = 0;
		break;
	}
	bzero(&smpls, sizeof(smpls));	
/*
 * Remove corrosponding llentry{}.
 */	
 	smpls.smpls_len = SMPLS_LEN;
	smpls.smpls_family = AF_MPLS;
 	
	if (mpls_flags(ifa) & RTF_PUSH) { 
		smpls.smpls_label = satosmpls_label(ifa->ifa_addr);
	} else {
		smpls.smpls_label = satosftn_label(ifa->ifa_dstaddr);
	}
	seg = (struct sockaddr *)&smpls;
	
	switch (ifp->if_type) {
	case IFT_ETHER:	
	case IFT_FDDI: 	
					/* FALLTHROUGH */
					
		lltable_prefix_free(seg->sa_family, seg, NULL, 0);		
		break;
	case IFT_LOOP:	
	case IFT_MPLS:
		break;
	default:
		break;
	}
	ifa->ifa_flags &= ~IFA_ROUTE;
/*
 * Unbound and dequeue nhlfe.
 */	
	if (mpls_flags(ifa) & RTF_LLDATA) {
		IF_AFDATA_LOCK(ifp);	
		if (MPLS_IFINFO_IFA(ifp) == ifa) {
			MPLS_IFINFO_IFA(ifp) = NULL;
			ifp->if_flags &= ~IFF_MPE;			
		}
		IF_AFDATA_WUNLOCK(ifp);
		ifa_free(ifa);
	}
	IF_ADDR_WLOCK(ifp);
	TAILQ_REMOVE(&ifp->if_addrhead, ifa, ifa_link);	
	IF_ADDR_WUNLOCK(ifp);
	
	ifa_free(ifa);
	
	NHLFE_WLOCK();
	TAILQ_REMOVE(&mpls_iflist, ifatomia(ifa), mia_link);	
	NHLFE_WUNLOCK();
/*
 * Finalize.
 */	
	bzero(seg, seg->sa_len);
	seg = (struct sockaddr *)&mpls_x(ifa);			
	bzero(seg, sizeof(mpls_x(ifa)));
	seg = (struct sockaddr  *)&mpls_seg(ifa);			
	bzero(seg, sizeof(mpls_seg(ifa)));
	seg = (struct sockaddr  *)&mpls_nh(ifa);			
	bzero(seg, sizeof(mpls_nh(ifa)));
	
	mpls_flags(ifa) = 0;	
	mpls_lle(ifa) = NULL;	
	
	ifa_free(ifa);
out:
	return (error);	
}

/*
 * Implements temporary queue, holds set containing 
 * nhlfe maps to fec during mpls_link_rtrequest.
 */
struct mpls_ifaddrbuf {
	TAILQ_ENTRY(mpls_ifaddrbuf)	ib_chain;
	struct ifaddr	*ib_nhlfe;
};
TAILQ_HEAD(mpls_ifaddrbuf_hd, mpls_ifaddrbuf);

/*
 * Purge ftn maps to fec, when fec invalidates. 
 *
 * XXX: incomplete...
 */
void
mpls_link_rtrequest(int cmd, struct rtentry *fec, struct rt_addrinfo *rti)
{
	struct mpls_ifaddrbuf_hd hd;
	
	struct ifnet *ifp;
	struct ifaddr *ifa;
	
	struct mpls_ifaddrbuf *ib;

#ifdef MPLS_DEBUG
	(void)printf("%s\n", __func__);
#endif /* MPLS_DEBUG */

	RT_LOCK_ASSERT(fec);
	TAILQ_INIT(&hd);
	ifp = fec->rt_ifp;

	switch (cmd) {
	case RTM_ADD:
		break;
	case RTM_CHANGE:	
	case RTM_DELETE:
/*
 * Build subset.
 */			
		IF_ADDR_RLOCK(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		
			if ((ifa->ifa_flags & IFA_NHLFE) == 0)
				continue;
				
			if (mpls_sa_equal(rt_key(fec), 
				(struct sockaddr *)&mpls_x(ifa)) == 0)
				continue;
	
			ifa_ref(ifa);
/*
 * Can't fail.
 */			
			ib = malloc(sizeof(*ib), M_TEMP, M_WAITOK|M_ZERO);
			ib->ib_nhlfe = ifa;	
			
			TAILQ_INSERT_TAIL(&hd, ib, ib_chain);
		}
		IF_ADDR_RUNLOCK(ifp);	
/*
 * Purge collection.
 */
		while (!TAILQ_EMPTY(&hd)) {
			ib = TAILQ_FIRST(&hd);
			
			(void)mpls_purgeaddr(ib->ib_nhlfe);     	 	
			
			TAILQ_REMOVE(&hd, ib, ib_chain);
			
			ifa_free(ib->ib_nhlfe);
			ib->ib_nhlfe = NULL;
			
			free(ib, M_TEMP);
		}
	    break;
	default:
		break;
	}			
	fec->rt_mtu = ifp->if_mtu;
}
#undef rti_dst
#undef rti_gateway
#undef rti_netmask
#undef rti_ifaaddr
#undef rti_ifpaddr
#undef rti_brd
#undef rti_flags
#undef rti_ifa
