/*
 *	BIRD Library -- Flow specification (RFC 5575)
 *
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/flowspec.h"

static const char* flow_err_str_[] = {
  [FLOW_VALID] = "FLOW_VALID",
  [FLOW_NOT_COMPLETE] = "FLOW_NOT_COMPLETE",
  [FLOW_UNKNOWN_COMPONENT] = "FLOW_UNKNOWN_COMPONENT",
  [FLOW_EXCEED_MAX_PREFIX_LENGTH] = "FLOW_EXCEED_MAX_PREFIX_LENGTH",
  [FLOW_BAD_TYPE_ORDER] = "FLOW_BAD_TYPE_ORDER",
  [FLOW_AND_BIT_SHOULD_BE_UNSET] = "FLOW_AND_BIT_SHOULD_BE_UNSET",
  [FLOW_ZERO_BIT_SHOULD_BE_UNSED] = "FLOW_ZERO_BIT_SHOULD_BE_UNSED",
  [FLOW_VALID] = "FLOW_VALID",
  [FLOW_DIDNT_MEET_DEST_PREFIX] = "FLOW_DIDNT_MEET_DEST_PREFIX",
};

const char *
flow_err_str(enum flow_err code)
{
  return flow_err_str_[code];
}

uint
flow_get_length(const byte *b)
{
  return ((*b & 0xf0) == 0xf0) ? get_u16(b) & 0x0fff : *b;
}

byte *
flow_set_length(byte *b, u16 len)
{
  if (len >= 0xf0)
  {
    put_u16(b, len | 0xf000);
    return b+2;
  }

  *b = len;
  return b+1;
}

/*
 * Flowspec iterators
 */

static const byte *
flow_first_part_(const byte *b)
{
  /* It is possible to encode <240 into 2 octet too */

  if (flow_get_length(b) == 0)
    return NULL;

  if ((b[0] & 0xf0) == 0xf0)
    return b + 2;

  return b + 1;
}

const byte *
flow_first_part(const net_addr_flow4 *f)
{
  return flow_first_part_(f->data);
}

/**
 * flow4_next_part -
 * @pos:
 * @end:
 *
 * It expects validated flow data.
 */
const byte *
flow4_next_part(const byte *pos, const byte *end)
{
  if (pos == NULL)
    bug("flow4_next_part: pos == NULL");

  switch (*pos++)
  {
  case FLOWS_TYPE_DST_PREFIX:
  case FLOWS_TYPE_SRC_PREFIX:
  {
    uint l = *pos++;
    uint b = (l + 7) / 8;
    pos += b;
    break;
  }

  case FLOWS_TYPE_IP_PROTOCOL:
  case FLOWS_TYPE_PORT:
  case FLOWS_TYPE_DST_PORT:
  case FLOWS_TYPE_SRC_PORT:
  case FLOWS_TYPE_ICMP_TYPE:
  case FLOWS_TYPE_ICMP_CODE:
  case FLOWS_TYPE_TCP_FLAGS:
  case FLOWS_TYPE_PACKET_LENGTH:
  case FLOWS_TYPE_DSCP:
  case FLOWS_TYPE_FRAGMENT:
  {
    /* Is this the end of list operator-value pair? */
    uint last = 0;

    while (!last)
    {
      last = *pos & 0x80;

      /* Value length of operator */
      uint len = 1 << ((*pos & 0x30) >> 4);
      pos += 1+len;
    }
    break;
  }
  default:
    return NULL;
  }

  return (pos < end) ? pos : NULL;
}

struct flow_validation
flow4_validate(const byte *nlri, uint len)
{
#define VALIDATION_STATE(x) ((struct flow_validation) {x, type, pos})
  enum flow_type type = 0;
  const byte *pos = nlri;
  const byte *end = nlri + len;
  int met_dst_pfx = 0;

  while (pos < end)
  {
    /* Check increasing type ordering */
    if (type >= *pos)
      return VALIDATION_STATE(FLOW_BAD_TYPE_ORDER);
    type = *pos;

    switch (*pos++)
    {
    case FLOWS_TYPE_DST_PREFIX:
      met_dst_pfx = 1;
      /* fall through */
    case FLOWS_TYPE_SRC_PREFIX:
    {
      uint l = *pos;
      if (l > IP4_MAX_PREFIX_LENGTH)
	return VALIDATION_STATE(FLOW_EXCEED_MAX_PREFIX_LENGTH);
      pos++;

      uint b = (l + 7) / 8;
      pos += b;

      break;
    }

    case FLOWS_TYPE_IP_PROTOCOL:
    case FLOWS_TYPE_PORT:
    case FLOWS_TYPE_DST_PORT:
    case FLOWS_TYPE_SRC_PORT:
    case FLOWS_TYPE_ICMP_TYPE:
    case FLOWS_TYPE_ICMP_CODE:
    case FLOWS_TYPE_TCP_FLAGS:
    case FLOWS_TYPE_PACKET_LENGTH:
    case FLOWS_TYPE_DSCP:
    case FLOWS_TYPE_FRAGMENT:
    {
      /* Is this the end of list operator-value pair? */
      uint last = 0;
      uint first = 1;

      while (!last)
      {
	/*
	 *    0   1   2   3   4   5   6   7
	 *  +---+---+---+---+---+---+---+---+
	 *  | e | a |  len  | 0 |lt |gt |eq |
	 *  +---+---+---+---+---+---+---+---+
	 *
	 *           Numeric operator
	 */

	last = *pos & 0x80;

	/* The AND bit should in the first operator byte of a sequence */
	if (first && (*pos & 0x40))
	  return VALIDATION_STATE(FLOW_AND_BIT_SHOULD_BE_UNSET);

	/* This bit should be zero */
	if (*pos & 0x08)
	  return VALIDATION_STATE(FLOW_ZERO_BIT_SHOULD_BE_UNSED);

	if (type == FLOWS_TYPE_TCP_FLAGS || type == FLOWS_TYPE_FRAGMENT)
	{
	  /*
	   *    0   1   2   3   4   5   6   7
	   *  +---+---+---+---+---+---+---+---+
	   *  | e | a |  len  | 0 | 0 |not| m |
	   *  +---+---+---+---+---+---+---+---+
	   *
	   *           Bitmask operand
	   */
	  if (*pos & 0x04)
	    return VALIDATION_STATE(FLOW_ZERO_BIT_SHOULD_BE_UNSED);
	}

	/* Value length of operator */
	uint len = 1 << ((*pos & 0x30) >> 4);
	pos += 1+len;

	if (pos > end && !last)
	  return VALIDATION_STATE(FLOW_NOT_COMPLETE);

	if (pos > (end+1))
	  return VALIDATION_STATE(FLOW_NOT_COMPLETE);

	first = 0;
      }
      break;
    }
    default:
      return VALIDATION_STATE(FLOW_UNKNOWN_COMPONENT);
    }
  }

  if (pos != end)
    return VALIDATION_STATE(FLOW_NOT_COMPLETE);

  if (!met_dst_pfx)
    return VALIDATION_STATE(FLOW_DIDNT_MEET_DEST_PREFIX);

  return VALIDATION_STATE(FLOW_VALID);
#undef VALIDATION_STATE
}

net_addr_flow4
flow_insert_part(const net_addr_flow4 *f, const byte *part, uint plen, pool *m)
{
  const byte *s_pos = flow_first_part(f);
  const byte *s_end = s_pos + flow_get_length(f->data) - 1;
  enum flow_type p_type = *part;

  while (s_pos && (*s_pos < p_type))
  {
    if (*s_pos == p_type)
      bug("Don't try to insert a same component type more than once");

    s_pos = flow4_next_part(s_pos, s_end);
  }

  uint new_size = plen + flow_get_length(f->data);

  net_addr_flow4 e = *f;
  e.data = mb_alloc(m, new_size + (new_size >= 0xf0 ? 2 : 1));
  byte *e_pos = flow_set_length(e.data, new_size);

  if (s_pos == NULL)
  {
    /*Append*/
    memcpy(e_pos, flow_first_part(f), flow_get_length(f->data));
    memcpy(e_pos + flow_get_length(f->data), part, plen);
  }
  else
  {
    /* Prepend/insert */
    uint prep_size = s_pos - flow_first_part(f);
    memcpy(e_pos, flow_first_part(f), prep_size);
    memcpy(e_pos + prep_size, part, plen);
    memcpy(e_pos + prep_size + plen, s_pos, flow_get_length(f->data) - prep_size);
  }

  return e;
}
