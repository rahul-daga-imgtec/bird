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
  FLOWS_TYPE_DST_PREFIX = 1,
  FLOWS_TYPE_SRC_PREFIX = 2,
  FLOWS_TYPE_IP_PROTOCOL = 3,
  FLOWS_TYPE_PORT = 4,
  FLOWS_TYPE_DST_PORT = 5,
  FLOWS_TYPE_SRC_PORT = 6,
  FLOWS_TYPE_ICMP_TYPE = 7,
  FLOWS_TYPE_ICMP_CODE = 8,
  FLOWS_TYPE_TCP_FLAGS = 9,
  FLOWS_TYPE_PACKET_LENGTH = 10,
  FLOWS_TYPE_DSCP = 11,		/* Diffserv Code Point */
  FLOWS_TYPE_FRAGMENT = 12,
};

enum flow_err {
  FLOW_UNKNOWN_COMPONENT,
  FLOW_VALID,
  FLOW_NOT_COMPLETE,
  FLOW_EXCEED_MAX_PREFIX_LENGTH,
  FLOW_BAD_TYPE_ORDER,
  FLOW_AND_BIT_SHOULD_BE_UNSET,
  FLOW_ZERO_BIT_SHOULD_BE_UNSED,
  FLOW_DIDNT_MEET_DEST_PREFIX,
};

const char *flow_err_str(enum flow_err code);

uint flow_get_length(const byte *b);
byte *flow_set_length(byte *b, u16 len);

const byte *flow_first_part(const net_addr_flow4 *f);
const byte *flow4_next_part(const byte *pos, const byte *end);

struct flow_validation {
  enum flow_err result;
  enum flow_type last_type;
  const byte *last_pos;
};

struct flow_validation flow4_validate(const byte *nlri, uint len);
net_addr_flow4 flow_insert_part(const net_addr_flow4 *f, const byte *part, uint plen, pool *m);

#endif /* _BIRD_FLOWSPEC_H_ */
