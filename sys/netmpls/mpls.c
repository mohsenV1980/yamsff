/*-
 * Copyright (c) 2014, 2015 Henning Matyschok
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
/*-
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (C) 2001 WIDE Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
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
 
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/malloc.h>
#include <sys/priv.h>
#include <sys/socket.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_llatbl.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#include <netmpls/mpls.h>
#include <netinet/in.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif /* INET6 */

extern int 	mpls_arpresolve(struct ifnet *, struct rtentry *, 
	struct mbuf *, struct sockaddr *, u_char *, struct llentry **);
extern int 	mpls_purgeaddr(struct ifaddr *);
extern int 	mpls_newaddrmsg(struct ifnet *, struct sockaddr *);

struct ifaddr * 	mpls_ifaof_ifpforlspdst(struct sockaddr *, 
	struct sockaddr *, struct ifnet *, int);
struct ifaddr * 	mpls_ifaof_ifpforlsp(struct sockaddr *, 
	struct ifnet *, int);
struct ifaddr * 	mpls_ifawithlsp_fib(struct sockaddr *, u_int, int);
struct ifaddr * 	mpls_ifaof_ifpforseg(struct sockaddr *, 
	struct ifnet *, int);
struct ifaddr * 	mpls_ifawithseg_fib(struct sockaddr *, u_int, int);
int 	mpls_ifawithseg_check_fib(struct sockaddr *, u_int);
struct ifaddr * 	mpls_ifawithsegdst_fib(struct sockaddr *, 
	struct sockaddr *, u_int, int);	
struct ifaddr * 	mpls_ifaof_ifpforsegdst(struct sockaddr *, 
	struct sockaddr *, struct ifnet *, int);
struct ifaddr * 	mpls_ifawithdst_fib(struct sockaddr *, int, u_int, int);
struct ifaddr * 	mpls_ifaof_ifpfordst(struct sockaddr *, int, 
	struct ifnet *, int);
struct ifaddr * 	mpls_ifaof_ifpforxconnect(struct sockaddr *, 
	struct sockaddr *, struct ifnet *, int);
struct ifaddr * 	mpls_ifawithxconnect_fib(struct sockaddr *, 
	struct sockaddr *, u_int, int);
int 	mpls_control(struct socket *, u_long, caddr_t, 
	struct ifnet *, struct thread *);

/*
 * Locate nhlfe by its particular lsp (seg_out) and dst.
 */
 
struct ifaddr *
mpls_ifaof_ifpforlspdst(struct sockaddr *seg, struct sockaddr *x, 
		struct ifnet *ifp, int getref)
{
	struct ifaddr *ifa;
	
	uint32_t af = AF_MPLS;
	uint32_t i; 
	
	struct sockaddr *sa;
	
	if (seg->sa_family != af)
		return (NULL);
	
	i = satosmpls_label(seg);
	
	IF_ADDR_RLOCK(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
	
		if ((ifa->ifa_flags & IFA_NHLFE) == 0)
			continue;
	
		if (ifa->ifa_addr->sa_family != af)
			continue;
	
		if (satosftn_label(ifa->ifa_dstaddr) != i) 
			continue;
		
		sa = (struct sockaddr *)&ifatonhlfe_x(ifa);

		if (mpls_sa_equal(sa, x)) {
			ifa_ref(ifa);
			break;
		}
		sa = NULL;
	}
	IF_ADDR_RUNLOCK(ifp);
	
	if (ifa && getref == 0)
		ifa_free(ifa);
			
	return (ifa);
}

/*
 * Locate nhlfe by its particular lsp (seg_out).
 */
 
struct ifaddr *
mpls_ifaof_ifpforlsp(struct sockaddr *seg, struct ifnet *ifp, int getref)
{
	struct ifaddr *ifa;
	
	uint32_t af = AF_MPLS;
	uint32_t i; 
	
	if (seg->sa_family != af)
		return (NULL);
	
	i = satosmpls_label(seg);
	
	IF_ADDR_RLOCK(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
	
		if ((ifa->ifa_flags & IFA_NHLFE) == 0)
			continue;
	
		if (ifa->ifa_addr->sa_family != af)
			continue;
		
		if (satosftn_label(ifa->ifa_dstaddr) == i) 
			break;
	}
	IF_ADDR_RUNLOCK(ifp);
	
	if (ifa && getref == 0)
		ifa_free(ifa);
			
	return (ifa);
}
 
struct ifaddr *
mpls_ifawithlsp_fib(struct sockaddr *seg, u_int fibnum, int getref)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	uint32_t af = AF_MPLS;
	uint32_t i; 
	
	if (seg->sa_family != af)
		return (NULL);
	
	i = satosmpls_label(seg);
	
	IFNET_RLOCK_NOSLEEP();
	TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
		
		if ((ifp->if_flags & IFF_MPLS) == 0)
			continue;
		
		if ((fibnum != RT_ALL_FIBS) && (ifp->if_fib != fibnum))
			continue;
			
		IF_ADDR_RLOCK(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			
			if ((ifa->ifa_flags & IFA_NHLFE) == 0)
				continue;
			
			if (ifa->ifa_addr->sa_family != af)
				continue;
			
			if (satosftn_label(ifa->ifa_dstaddr) == i) {
				ifa_ref(ifa);
				IF_ADDR_RUNLOCK(ifp);
				goto done;
			}
		}
		IF_ADDR_RUNLOCK(ifp);
	}
	ifa = NULL;
done:
	IFNET_RUNLOCK_NOSLEEP();
	
	if (ifa && getref == 0)
		ifa_free(ifa);
	return (ifa);
}

/*
 * Locate nhlfe by its key (seg_in).
 */

struct ifaddr *
mpls_ifaof_ifpforseg(struct sockaddr *seg, struct ifnet *ifp, int getref)
{
	struct ifaddr *ifa;
	
	uint32_t af = AF_MPLS;
	uint32_t i; 
	
	if (seg->sa_family != af)
		return (NULL);
	
	i = satosmpls_label(seg);
	
	IF_ADDR_RLOCK(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
	
		if ((ifa->ifa_flags & IFA_NHLFE) == 0)
			continue;
	
		if (ifa->ifa_addr->sa_family != af)
			continue;
		
		if (satosmpls_label(ifa->ifa_addr) == i) 
			break;
	}
	IF_ADDR_RUNLOCK(ifp);
	
	if (ifa && getref == 0)
		ifa_free(ifa);
			
	return (ifa);
}

struct ifaddr *
mpls_ifawithseg_fib(struct sockaddr *seg, u_int fibnum, int getref)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	uint32_t af = AF_MPLS;
	uint32_t i; 
	
	if (seg->sa_family != af)
		return (NULL);
	
	i = satosmpls_label(seg);
	
	IFNET_RLOCK_NOSLEEP();
	TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
		
		if ((ifp->if_flags & IFF_MPLS) == 0)
			continue;
		
		if ((fibnum != RT_ALL_FIBS) && (ifp->if_fib != fibnum))
			continue;
			
		IF_ADDR_RLOCK(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			
			if ((ifa->ifa_flags & IFA_NHLFE) == 0)
				continue;
			
			if (ifa->ifa_addr->sa_family != af)
				continue;
			
			if (satosmpls_label(ifa->ifa_addr) == i) {
				ifa_ref(ifa);
				IF_ADDR_RUNLOCK(ifp);
				goto done;
			}
		}
		IF_ADDR_RUNLOCK(ifp);
	}
	ifa = NULL;
done:
	IFNET_RUNLOCK_NOSLEEP();
	
	if (ifa && getref == 0)
		ifa_free(ifa);
	return (ifa);
}

int
mpls_ifawithseg_check_fib(struct sockaddr *seg, u_int fibnum)
{
	return (mpls_ifawithseg_fib(seg, fibnum, 0) != NULL);
}
 
/*
 * Locate nhlfe globally by its key (seg_in) and 
 * argument (x) for inclusion mapping on fec .
 */
 
struct ifaddr *
mpls_ifawithsegdst_fib(struct sockaddr *seg, struct sockaddr *x, 
	u_int fibnum, int getref)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	
	uint32_t af = AF_MPLS;
	uint32_t i; 
	
	struct sockaddr *sa;
	
	if (seg->sa_family != af)
		return (NULL);
	
	i = satosmpls_label(seg);
	
	IFNET_RLOCK_NOSLEEP();
	TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
		
		if ((ifp->if_flags & IFF_MPLS) == 0)
			continue;
			
		if ((fibnum != RT_ALL_FIBS) && (ifp->if_fib != fibnum))
			continue;
			
		IF_ADDR_RLOCK(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			
			if ((ifa->ifa_flags & IFA_NHLFE) == 0)
				continue;
			
			if (ifa->ifa_addr->sa_family != af)
				continue;
			
			if (satosmpls_label(ifa->ifa_addr) != i) 
				continue;
			
			sa = (struct sockaddr *)&ifatonhlfe_x(ifa);
			
			if (mpls_sa_equal(sa, x)) {
				ifa_ref(ifa);
				IF_ADDR_RUNLOCK(ifp);
				goto done;
			}
			sa = NULL;
		}
		IF_ADDR_RUNLOCK(ifp);
	}
	ifa = NULL;
done:
	IFNET_RUNLOCK_NOSLEEP();
	
	if (ifa && getref == 0)
		ifa_free(ifa);
	return (ifa);
}

struct ifaddr *
mpls_ifaof_ifpforsegdst(struct sockaddr *seg, struct sockaddr *x, 
		struct ifnet *ifp, int getref)
{
	struct ifaddr *ifa;
	
	uint32_t af = AF_MPLS;
	uint32_t i; 
	
	struct sockaddr *sa;
	
	if (seg->sa_family != af)
		return (NULL);
	
	i = satosmpls_label(seg);
	
	IF_ADDR_RLOCK(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
	
		if ((ifa->ifa_flags & IFA_NHLFE) == 0)
			continue;
	
		if (ifa->ifa_addr->sa_family != af)
			continue;
	
		if (satosmpls_label(ifa->ifa_addr) != i) 
			continue;
		
		sa = (struct sockaddr *)&ifatonhlfe_x(ifa);

		if (mpls_sa_equal(sa, x)) {
			ifa_ref(ifa);
			break;
		}
		sa = NULL;
	}
	IF_ADDR_RUNLOCK(ifp);
	
	if (ifa && getref == 0)
		ifa_free(ifa);
			
	return (ifa);
}

/*
 * Locate nhlfe by destination (x).
 */
 
struct ifaddr *
mpls_ifawithdst_fib(struct sockaddr *x, int flags, u_int fibnum, int getref)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	
	uint32_t af = AF_MPLS;
	
	struct sockaddr *sa;
	
	IFNET_RLOCK_NOSLEEP();
	TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
		
		if ((ifp->if_flags & IFF_MPLS) == 0)
			continue;
			
		if ((fibnum != RT_ALL_FIBS) && (ifp->if_fib != fibnum))
			continue;
			
		IF_ADDR_RLOCK(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			
			if ((ifa->ifa_flags & IFA_NHLFE) == 0)
				continue;
			
			if (ifa->ifa_addr->sa_family != af)
				continue;
			
			if (mpls_sa_equal(sa, x) == 0) 
				continue;
		
			if (ifatonhlfe_flags(ifa) & flags) {
				ifa_ref(ifa);
				IF_ADDR_RUNLOCK(ifp);
				goto done;
			}
			sa = NULL;
		}
		IF_ADDR_RUNLOCK(ifp);
	}
	ifa = NULL;
done:
	IFNET_RUNLOCK_NOSLEEP();
	
	if (ifa && getref == 0)
		ifa_free(ifa);
	return (ifa);
}

struct ifaddr *
mpls_ifaof_ifpfordst(struct sockaddr *x, int flags, 
		struct ifnet *ifp, int getref)
{
	struct ifaddr *ifa;
	
	uint32_t af = AF_MPLS;
	
	struct sockaddr *sa;

	IF_ADDR_RLOCK(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
	
		if ((ifa->ifa_flags & IFA_NHLFE) == 0)
			continue;
	
		if (ifa->ifa_addr->sa_family != af)
			continue;
		
		sa = (struct sockaddr *)&ifatonhlfe_x(ifa);

		if (mpls_sa_equal(sa, x) == 0) 
			continue;
		
		if (ifatonhlfe_flags(ifa) & flags) {
			ifa_ref(ifa);
			break;
		}
		sa = NULL;
	}
	IF_ADDR_RUNLOCK(ifp);
	
	if (ifa && getref == 0)
		ifa_free(ifa);
			
	return (ifa);
}

/*
 * Locate nhlfe by key (seg_in) -> (nh) x < op, seg_out, rd >  on ftn.
 */
 
struct ifaddr *
mpls_ifaof_ifpforxconnect(struct sockaddr *seg, struct sockaddr *nh, 
		struct ifnet *ifp, int getref)
{
	struct ifaddr *ifa;
	
	uint32_t af = AF_MPLS;
	uint32_t len = SFTN_LEN;
	uint32_t i; 
	
	if (seg->sa_family != af)
		return (NULL);
	
	if (nh->sa_len != len)
		return (NULL);
	
	i = satosmpls_label(seg);
	
	IF_ADDR_RLOCK(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
	
		if ((ifa->ifa_flags & IFA_NHLFE) == 0)
			continue;
			
		if (ifa->ifa_addr->sa_family != af)
			continue;
			
		if (satosmpls_label(ifa->ifa_addr) != i) 
			continue;
			
#ifdef MPLS_DEBUG
		if (ifa->ifa_dstaddr->sa_len != len)
			continue;	
#endif /* MPLS_DEBUG */		
		
		if (mpls_sa_equal(ifa->ifa_dstaddr, nh)) {
			ifa_ref(ifa);
			IF_ADDR_RUNLOCK(ifp);
			break;
		}
	}
	IF_ADDR_RUNLOCK(ifp);
	
	if (ifa && getref == 0)
		ifa_free(ifa);
			
	return (ifa);
}
 
struct ifaddr *
mpls_ifawithxconnect_fib(struct sockaddr *seg, struct sockaddr *nh, 
		u_int fibnum, int getref)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	
	uint32_t af = AF_MPLS;
	uint32_t len = SFTN_LEN;
	uint32_t i; 
	
	if (seg->sa_family != af)
		return (NULL);
	
	if (nh->sa_len != len)
		return (NULL);
	
	i = satosmpls_label(seg);
	
	IFNET_RLOCK_NOSLEEP();
	TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
		
		if ((ifp->if_flags & IFF_MPLS) == 0)
			continue;
			
		if ((fibnum != RT_ALL_FIBS) && (ifp->if_fib != fibnum))
			continue;
			
		IF_ADDR_RLOCK(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			
			if ((ifa->ifa_flags & IFA_NHLFE) == 0)
				continue;
			
			if (ifa->ifa_addr->sa_family != af)
				continue;
			
			if (satosmpls_label(ifa->ifa_addr) != i) 
				continue;
		
#ifdef MPLS_DEBUG
			if (ifa->ifa_dstaddr->sa_len != len)
				continue;	
#endif /* MPLS_DEBUG */	
		
			if (mpls_sa_equal(ifa->ifa_dstaddr, nh)) {
				ifa_ref(ifa);
				IF_ADDR_RUNLOCK(ifp);
				goto done;
			}
		}
		IF_ADDR_RUNLOCK(ifp);
	}
	ifa = NULL;
done:
	IFNET_RUNLOCK_NOSLEEP();
	
	if (ifa && getref == 0)
		ifa_free(ifa);
	return (ifa);
}

/*
 * Generic mpls control operations provides
 * bindings on per-interface label space. 
 */ 

int
mpls_control(struct socket *so __unused, u_long cmd, caddr_t data, 
		struct ifnet *ifp, struct thread *td)
{
	struct ifreq *ifr = (struct ifreq *)data;
	struct ifaddr *ifa = NULL;
	struct sockaddr *seg;
	
	int error, priv;
		
	if (ifp == NULL)
		return (EADDRNOTAVAIL);
	
	if ((ifp->if_ioctl == NULL) 
		|| (ifp->if_addr == NULL)) 
		return (ENXIO);

	if ((ifp->if_flags & IFF_MPLS) == 0) 
		return (EADDRNOTAVAIL);
	
	if (ifr == NULL) 
		return (EINVAL);

	IF_AFDATA_RLOCK(ifp);	
	ifa = MPLS_IFINFO_IFA(ifp);
	IF_AFDATA_RUNLOCK(ifp);
	
	if (ifa != NULL) 
		ifa_ref(ifa);
	
	seg = &ifr->ifr_addr;
	priv = 0;
	
	switch (cmd) {
	case SIOCAIFADDR: 
 	case SIOCSIFADDR: 	
/*
 * Request MPLS label binding on selected interface.
 */				
		error = mpls_sa_validate(seg, AF_MPLS);
		if (error != 0)
			break;	
	
		priv = PRIV_NET_ADDIFADDR;
			
							/* FALLTHROUGH */	
	case SIOCDIFADDR:
/*
 * Delete MPLS label binding.
 */				
 		if (priv != PRIV_NET_ADDIFADDR)
			priv = PRIV_NET_DELIFADDR;
 		
 		error = priv_check(td, priv);
		if (error != 0) 
			break;
 		
		if (ifa != NULL) 
			error = mpls_purgeaddr(ifa);
	
		if (cmd == SIOCDIFADDR) 
			break;
		
		if (error == 0)			
			error = mpls_newaddrmsg(ifp, seg);
		break;
	case SIOCGIFADDR:
		error = 0;
		break;
	default:
	
		error = (*ifp->if_ioctl)(ifp, cmd, data);
		break;
	}	
	
	if (ifa != NULL)
		ifa_free(ifa);		

	return (error);	
}

/*
 * Following lltable{} specific functions and procedures are 
 * derived from present implementation of IPv4 protocol stack. 
 * 
 * See netinet/in.c, netinet/if_ether.c and net/if_llatabl.c
 * for further details. 
 */

struct mpls_llentry {
	struct llentry		ml_base;	/* corrosponding lla */
	struct sockaddr_mpls	ml_seg;	/* particular lsp */
};

static void
mpls_lltable_free(struct lltable *llt, struct llentry *lle)
{
	LLE_WLOCK_ASSERT(lle);
	LLE_WUNLOCK(lle);
	LLE_LOCK_DESTROY(lle);
	
	free(lle, M_LLTABLE);
}

/*
 * Dtor, find llentry{} by out-segmentand release bound ressources.. 
 */
static void
mpls_lltable_prefix_free(struct lltable *llt, const struct sockaddr *sa0,
   		const struct sockaddr *sa1, u_int flags)
{
	const struct sockaddr_mpls *seg = (const struct sockaddr_mpls *)sa0;
	int i;
	struct llentry *lle, *next;
	size_t pkts_dropped;

	IF_AFDATA_WLOCK(llt->llt_ifp);
	
	for (i = 0; i < LLTBL_HASHTBL_SIZE; i++) {
		LIST_FOREACH_SAFE(lle, &llt->lle_head[i], lle_next, next) {

			if (MPLS_SEG(lle)->smpls_label != seg->smpls_label) 
				continue;
				
			LLE_WLOCK(lle);
			LLE_REMREF(lle);
			pkts_dropped = llentry_free(lle);		
		}
	}	
	IF_AFDATA_WUNLOCK(llt->llt_ifp);
}

/*
 * Ctor, map particular lsp to corrosponding link layer interface.
 */
static struct llentry *
mpls_lltable_new(const struct sockaddr *sa, u_int flags)
{
	const struct sockaddr_mpls *seg = (const struct sockaddr_mpls *)sa;
	struct llentry *lle = NULL;
	struct mpls_llentry *ml;

#ifdef MPLS_DEBUG
	KASSERT((seg != NULL), ("segment not defined"));
#endif /* MPLS_DEBUG */	
	
	if ((ml = malloc(sizeof(*ml), M_LLTABLE, M_NOWAIT|M_ZERO)) == NULL)		
		goto out;

	ml->ml_seg = *seg;
	lle = &ml->ml_base;
	
	LLE_LOCK_INIT(lle);
	
	lle->la_expire = time_uptime;
	lle->lle_refcnt = 1;
	lle->lle_free = mpls_lltable_free;
out:
	return (lle);
}

/*
 * Returns locked llentry{} from cache.
 */
static struct llentry *
mpls_lltable_lookup(struct lltable *llt, u_int flags, const struct sockaddr *sa)
{
	const struct sockaddr_mpls *seg = (const struct sockaddr_mpls *)sa;
	struct llentry *lle = NULL;
	u_int hashkey;
	struct llentries *lleh;
	
	IF_AFDATA_LOCK_ASSERT(llt->llt_ifp);
	
	hashkey = seg->smpls_label & MPLS_LABEL_MASK;
	lleh = &llt->lle_head[LLATBL_HASH(hashkey, LLTBL_HASHMASK)];

	LIST_FOREACH(lle, lleh, lle_next) {
		
		if (lle->la_flags & LLE_DELETED)
			continue;
		
		if (MPLS_SEG(lle)->smpls_label == seg->smpls_label)
			break;
	}
/*
 * Create llentry{}.
 */	
	if (lle == NULL) {
		
#ifdef MPLS_DEBUG
		if (flags & LLE_DELETE)
			log(LOG_INFO, "mpls label is missing from cache = %d  "
				"in delete\n", seg->smpls_label);
#endif
		
		if ((flags & LLE_CREATE) == 0) {
			lle = NULL;
			goto out;
		}
		
		if ((lle = mpls_lltable_new(sa, flags)) == NULL) {
			log(LOG_INFO, "lla_lookup: new lle malloc failed\n");
			goto out;
		}
		lle->la_flags = flags & ~LLE_CREATE;
		
		if ((flags & (LLE_CREATE|LLE_IFADDR)) 
			== (LLE_CREATE|LLE_IFADDR)) {
			bcopy(IF_LLADDR(llt->llt_ifp), &lle->ll_addr, 
				llt->llt_ifp->if_addrlen);
		}
		lle->lle_tbl  = llt;
		lle->lle_head = lleh;
		lle->la_flags |= LLE_LINKED;
		
		LIST_INSERT_HEAD(lleh, lle, lle_next);
	
	} else if (flags & LLE_DELETE) {
/*
 * Finalize llentry{}.
 */
		if (((lle->la_flags & LLE_IFADDR) == 0) 
			|| (flags & LLE_IFADDR)) {
			
			LLE_WLOCK(lle);
			
			lle->la_flags |= LLE_DELETED;
			llentry_free(lle);
			LLE_WUNLOCK(lle);
		}
		lle = (void *)-1;
	}
	
	if (LLE_IS_VALID(lle)) {
		if (flags & LLE_EXCLUSIVE)
			LLE_WLOCK(lle);
		else
			LLE_RLOCK(lle);
	}
out:
	return (lle);
}

/*
 * Dumps entire cache.
 * 
 * XXX: untested...
 */
static int
mpls_lltable_dump(struct lltable *llt, struct sysctl_req *wr)
{
	struct llentry *lle;
	struct {
		struct rt_msghdr	rtm;
		struct sockaddr_mpls	seg;
		struct sockaddr_dl	sdl;
	} arpc;
	int error, i;

	LLTABLE_LOCK_ASSERT();

	for (error = 0, i = 0; i < LLTBL_HASHTBL_SIZE; i++) {
		
		LIST_FOREACH(lle, &llt->lle_head[i], lle_next) {
/* 
 * Skip deleted entries. 
 */
			if ((lle->la_flags & LLE_DELETED) == LLE_DELETED)
				continue;
				
			bzero(&arpc, sizeof(arpc));	
/*
 * Prepare buffer denotes SPI containing cached llentry{}.
 */		
			arpc.rtm.rtm_msglen = sizeof(arpc);
			arpc.rtm.rtm_version = RTM_VERSION;
			arpc.rtm.rtm_type = RTM_GET;
			arpc.rtm.rtm_flags = RTF_UP;
			arpc.rtm.rtm_addrs = RTA_DST | RTA_GATEWAY;

			arpc.seg.smpls_family = AF_MPLS;
			arpc.seg.smpls_len = sizeof(arpc.seg);
			arpc.seg.smpls_label = MPLS_SEG(lle)->smpls_label;

			if (lle->la_flags & LLE_PUB) 
				arpc.rtm.rtm_flags |= RTF_ANNOUNCE;

			arpc.sdl.sdl_family = AF_LINK;
			arpc.sdl.sdl_len = sizeof(arpc.sdl);
			arpc.sdl.sdl_index = llt->llt_ifp->if_index;
			arpc.sdl.sdl_type = llt->llt_ifp->if_type;
			
			if ((lle->la_flags & LLE_VALID) == LLE_VALID) {
				arpc.sdl.sdl_alen = llt->llt_ifp->if_addrlen;
				bcopy(&lle->ll_addr, LLADDR(&arpc.sdl), 
					llt->llt_ifp->if_addrlen);
			} else {
				arpc.sdl.sdl_alen = 0;
				bzero(LLADDR(&arpc.sdl), llt->llt_ifp->if_addrlen);
			}
			arpc.rtm.rtm_rmx.rmx_expire = lle->la_expire;
			arpc.rtm.rtm_flags |= (RTF_HOST | RTF_LLDATA);
			arpc.rtm.rtm_index = llt->llt_ifp->if_index;
/*
 * Send SPI to caller.
 */			
			if ((error = SYSCTL_OUT(wr, &arpc, sizeof(arpc))) != 0)
				break;
		}
	}	
	return (error);
}

extern int	mpls_output(struct ifnet *, struct mbuf *, struct sockaddr *,
	struct route *ro);
void *	mpls_domifattach(struct ifnet *);
void	mpls_domifdetach(struct ifnet *, void *);

/*
 * Bind cache. 
 *
 * See kern/uiopc_domain.c and net/if.c for further details.
 */
void *
mpls_domifattach(struct ifnet *ifp)
{
	struct mpls_ifinfo *mii = NULL;
	struct lltable *llt;

	if (ifp == NULL)
		goto out;

	mii = malloc(sizeof(*mii), M_IFADDR, M_WAITOK|M_ZERO);
	
	if ((llt = lltable_init(ifp, AF_MPLS)) != NULL) {
		llt->llt_prefix_free = mpls_lltable_prefix_free;
		llt->llt_lookup = mpls_lltable_lookup;
		llt->llt_dump = mpls_lltable_dump;
		
		mii->mii_llt = llt;
	} else {
		free(mii, M_IFADDR);
		mii = NULL;
	}
out:
	return (mii);
}

/*
 * Detach cache.
 */
void
mpls_domifdetach(struct ifnet *ifp, void *aux)
{
	struct mpls_ifinfo *mii;
	struct lltable *llt;
	
	if ((mii = (struct mpls_ifinfo *)aux) == NULL)
		return;

	if (ifp == NULL)
		return;
		
	if ((llt = mii->mii_llt) == NULL)
		return;

	switch (ifp->if_type) {
	case IFT_ETHER:
	case IFT_VETHER:
	case IFT_FDDI:
	case IFT_LOOP:
		
		if (ifp->if_flags & IFF_MPLS) {
			ifp->if_flags &= ~IFF_MPLS;
			ifp->if_output = mii->mii_output;
		}
		break;
	case IFT_MPLS: 
		break;
	default:
		break;
	}
	lltable_free(llt);
	free(mii, M_IFADDR);
} 


