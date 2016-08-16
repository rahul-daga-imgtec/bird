/*
 *	BIRD -- MPLS central hub
 *
 *	(c) 2016 Jan Moskyto Matejka <mq@ucw.cz>
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: MPLS
 *
 * This protocol is a governor over its MPLS table. It maintains the MPLS
 * routes in that table to match the MPLS enabled IP routing tables.
 *
 * This protocol is the authority that assigns the MPLS labels. It also
 * maintains route labelling according to neighbors' LIBs.
 *
 * Route labelling (neighbor labels):
 * a) the protocol may import a route with a full neighbor's MPLS stack. This
 *    may happen e.g. for single hop labeled BGP. Nothing more is needed to do.
 * b) the protocol may import a route with a recursive nexthop and partial MPLS
 *    stack (according to that nexthop). The route gets resolved via hostentry
 *    and prepended the appropriate MPLS stack for the neighbor. This may
 *    happen e.g. for multihop labeled BGP.
 * c) the protocol may be MPLS unaware at all. Then the MPLS labeling pipeline
 *    is activated and the route gets its libentry. The MPLS labels may then
 *    change even when no route change appears. This may happen e.g. for OSPF
 *    which is then labeled by e.g. LDP.
 *
 * Note: Recursive routes (nexthops) cannot be labeled externally. The only
 * source of label stack in recursive nexthop is the importing protocol itself.
 *
 * Label assignments (local labels):
 * a) the protocol may ignore label assignments at all. Then the MPLS protocol
 *    assigns a label to every route, one label per destination
 * b) the protocol may request a label and then import a MPLS route specifying
 *    what to do with that label
 *
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "lib/hash.h"
#include "lib/mpls.h"

#include "proto/mpls/mpls.h"

#define MPLS_MAPPING_EQ(a, b) net_equal(a, b)
#define MPLS_MAPPING_FN(n) net_hash(n)
#define MPLS_MAPPING_KEY(nn) (&((nn)->nu.n))
#define MPLS_MAPPING_NEXT(nn) (nn->next)
#define MPLS_MAPPING_PARAMS		/8, *2, 2, 2, 6, 20
#define MPLS_MAPPING_REHASH mpls_mapping_rehash

HASH_DEFINE_REHASH_FN(MPLS_MAPPING, struct mpls_mapping)

static u32
mpls_label_find(struct mpls_proto *p, net_addr *n)
{
  struct mpls_mapping *mm = HASH_FIND(p->map_net, MPLS_MAPPING, n);
  if (mm)
    return mm->label;
  else
    return MPLS_LABEL_UNKNOWN;
}

static u32
mpls_label_get(struct mpls_proto *p, net_addr *n, rte *e, ea_list *ea)
{
  struct mpls_mapping *mm = HASH_FIND(p->map_net, MPLS_MAPPING, n);
  if (mm)
    goto have;

  mm = sl_alloc(p->map_slab);
  net_copy(&(mm->nu.n), n);

  mm->label = idm_alloc(&(p->map_idm));
  if (mm->label >= p->map_label_size)
  {
    p->map_label = mb_realloc(p->map_label, sizeof(struct mpls_mapping *) * p->map_label_size * 2);
    p->map_label_size *= 2;
  }
  p->map_label[mm->label] = mm;
  HASH_INSERT2(p->map_net, MPLS_MAPPING, p->p.pool, mm);

  rta *a = alloca(rta_size(e->attrs));
  memcpy(a, e->attrs, rta_size(e->attrs));
  a->src = p->p.main_source;
  a->source = RTS_MPLS;
  a->aflags = 0;
  a->eattrs = ea;
  a->hostentry = NULL;

  rte *ee = rte_get_temp(a);
  ee->pref = e->pref;
  ee->pflags = e->pflags;

  net_addr_union nu;
  net_fill_mpls(&nu.n, mm->label);
  rte_update2(p->mpls_channel, &(nu.n), ee, p->p.main_source);

have:
  mm->cnt++;
  return mm->label;
}

static void
mpls_label_free(struct mpls_proto *p, u32 label)
{
  struct mpls_mapping *mm = p->map_label[label];
  if (!mm)
    return;

  if (--(mm->cnt))
    return;

  p->map_label[label] = NULL;
  HASH_REMOVE2(p->map_net, MPLS_MAPPING, p->p.pool, mm);
  idm_free(&(p->map_idm), mm->label);
  sl_free(p->map_slab, mm);

  net_addr_union nu;
  net_fill_mpls(&nu.n, mm->label);
  rte_update2(p->mpls_channel, &(nu.n), NULL, p->p.main_source);
}

static net_addr *
mpls_label_to_net(struct mpls_proto *p, u32 label)
{
  return p->map_label[label] ? &(p->map_label[label]->nu.n) : NULL;
}

static void
mpls_rt_notify(struct proto *P, struct channel *ch, net *n, rte *new, rte *old, ea_list *ea)
{
  struct mpls_proto *p = (struct mpls_proto *) P;
  if (ch == p->mpls_channel)
  {
    log(L_WARN "%s: Got rt_notify from MPLS table", P->name);
    return;
  }

  u32 label;
  if (!new) /* Withdrawal */
  {
    label = mpls_label_find(p, n->n.addr);
    if (label == MPLS_LABEL_UNKNOWN)
      return;

    mpls_label_free(p, label);
    return;
  }

  if (old)
    label = mpls_label_find(p, n->n.addr);
  else
    label = mpls_label_get(p, n->n.addr, new, ea);
}

static void
mpls_postconfig(struct proto_config *CF)
{
  struct mpls_config *c = (struct mpls_config *) CF;
  if (!c->mpls_channel)
    cf_error("MPLS channel must be configured in MPLS protocol");
}

static struct proto *
mpls_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct mpls_proto *p = (struct mpls_proto *) P;

  struct channel_config *cc;
  WALK_LIST(cc, CF->channels)
    if (cc->net_type == NET_MPLS)
      p->mpls_channel = proto_add_channel(P, cc);
    else
      proto_add_channel(P, cc);

  P->rt_notify = mpls_rt_notify;

  return P;
}

static int
mpls_start(struct proto *P)
{
  struct mpls_proto *p = (struct mpls_proto *) P;

  idm_init(&(p->map_idm), P->pool, 8);
  HASH_INIT(p->map_net, P->pool, 8);
  p->map_label_size = 256;
  p->map_label = mb_allocz(P->pool, sizeof(struct mpls_mapping *) * p->map_label_size);
  p->map_slab = sl_new(P->pool, sizeof(struct mpls_mapping));

  struct channel *ch;
  WALK_LIST(ch, p->p.channels)
    if (ch->table->mpls_flags & RT_MPLS_LABELED)
    {
      log(L_ERR "%s: Cannot start MPLS protocol: Table %s already labeled by another instance", p->p.name, ch->table->name);
      return PS_START;
    }

  WALK_LIST(ch, p->p.channels)
    ch->table->mpls_flags |= RT_MPLS_LABELED;

  return PS_UP;
}

static int
mpls_shutdown(struct proto *P)
{
  struct channel *ch;
  WALK_LIST(ch, P->channels)
    ch->table->mpls_flags &= ~RT_MPLS_LABELED;

  return PS_DOWN;
}

static int
mpls_reconfigure(struct proto *p, struct proto_config *c)
{
  return 1;
}

struct protocol proto_mpls = {
  .name =		"MPLS",
  .template =		"mpls%d",
  .preference =		DEF_PREF_MPLS,
  .channel_mask =	NB_IP | NB_MPLS,
  .proto_size =		sizeof(struct mpls_proto),
  .config_size =	sizeof(struct mpls_config),
  .postconfig =		mpls_postconfig,
  .init =		mpls_init,
  .start =		mpls_start,
  .shutdown =		mpls_shutdown,
  .reconfigure =	mpls_reconfigure,
};


