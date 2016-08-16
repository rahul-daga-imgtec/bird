#ifndef _BIRD_PROTO_MPLS_H_
#define _BIRD_PROTO_MPLS_H_

#include "lib/idm.h"
#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/route.h"

struct mpls_config {
  struct proto_config c;
  u8 mpls_channel; /* check (bool) whether there is a MPLS channel configured */
};

struct mpls_proto {
  struct proto p;
  struct channel *mpls_channel;
  struct idm map_idm;			// Label allocator
  HASH(struct mpls_mapping) map_net;	// Hash keyed by net
  struct mpls_mapping **map_label;	// Growing array indexed by label
  u32 map_label_size;			// Allocated size of that array
  slab *map_slab;			// Slab to allocate mpls mappings
};

struct mpls_mapping {
  struct mpls_mapping *next;	// Next in hash
  u32 label;			// MPLS label
  u32 cnt;			// Number of exported routes
  net_addr_union nu;		// Assigned address
};

#endif
