/*
 *	BIRD Library -- Flow specification (RFC 5575)
 *
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_FLOWSPEC_H_
#define _BIRD_FLOWSPEC_H_

enum flow_type {
  FLOW_TYPE_DST_PREFIX = 1,
  FLOW_TYPE_SRC_PREFIX = 2,
  FLOW_TYPE_IP_PROTOCOL = 3,
  FLOW_TYPE_NEXT_HEADER = 3,	/* IPv6 */
  FLOW_TYPE_PORT = 4,
  FLOW_TYPE_DST_PORT = 5,
  FLOW_TYPE_SRC_PORT = 6,
  FLOW_TYPE_ICMP_TYPE = 7,
  FLOW_TYPE_ICMP_CODE = 8,
  FLOW_TYPE_TCP_FLAGS = 9,
  FLOW_TYPE_PACKET_LENGTH = 10,
  FLOW_TYPE_DSCP = 11,		/* Diffserv Code Point */
  FLOW_TYPE_FRAGMENT = 12,
  FLOW_TYPE_LABEL = 13,		/* IPv6 */
};

net_addr_flow4 flow4_insert_part(const net_addr_flow4 *f, const byte *part, uint p_len, pool *mp);
net_addr_flow6 flow6_insert_part(const net_addr_flow6 *f, const byte *part, uint p_len, pool *mp);

/* Length */

u16 flow4_get_length(const net_addr_flow4 *f);
u16 flow6_get_length(const net_addr_flow6 *f);

void flow4_set_length(net_addr_flow4 *f, u16 len);
void flow6_set_length(net_addr_flow6 *f, u16 len);

/* Iterators */

const byte *flow4_first_part(const net_addr_flow4 *f);
const byte *flow6_first_part(const net_addr_flow6 *f);

const byte *flow4_next_part(const byte *pos, const byte *end);
const byte *flow6_next_part(const byte *pos, const byte *end);

/* Validation */

enum flow_state {
  FLOW_ST_UNKNOWN_COMPONENT,
  FLOW_ST_VALID,
  FLOW_ST_NOT_COMPLETE,
  FLOW_ST_EXCEED_MAX_PREFIX_LENGTH,
  FLOW_ST_BAD_TYPE_ORDER,
  FLOW_ST_AND_BIT_SHOULD_BE_UNSET,
  FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED,
  FLOW_ST_DEST_PREFIX_REQUIRED,
};

const char *flow_state_str(enum flow_state code);

struct flow_validation {
  enum flow_state result;
  enum flow_type last_type;
  const byte *last_pos;
};

struct flow_validation flow4_validate(const byte *nlri, uint len);
struct flow_validation flow6_validate(const byte *nlri, uint len);

#endif /* _BIRD_FLOWSPEC_H_ */
