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
  [FLOW_ST_UNKNOWN_COMPONENT] = "UNKNOWN_COMPONENT",
  [FLOW_ST_VALID] = "VALID",
  [FLOW_ST_NOT_COMPLETE] = "NOT_COMPLETE",
  [FLOW_ST_EXCEED_MAX_PREFIX_LENGTH] = "EXCEED_MAX_PREFIX_LENGTH",
  [FLOW_ST_BAD_TYPE_ORDER] = "BAD_TYPE_ORDER",
  [FLOW_ST_AND_BIT_SHOULD_BE_UNSET] = "AND_BIT_SHOULD_BE_UNSET",
  [FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED] = "ZERO_BIT_SHOULD_BE_UNSED",
  [FLOW_ST_DEST_PREFIX_REQUIRED] = "DEST_PREFIX_REQUIRED",
};

const char *
flow_state_str(enum flow_state code)
{
  return flow_err_str_[code];
}



static u16
flow_get_length(const byte *data)
{
  if (!data)
    return 0;

  return ((*data & 0xf0) == 0xf0) ? get_u16(data) & 0x0fff : *data;
}

u16
flow4_get_length(const net_addr_flow4 *f)
{
  return (f ? flow_get_length(f->data) : 0);
}

u16
flow6_get_length(const net_addr_flow6 *f)
{
  return (f ? flow_get_length(f->data) : 0);
}



static void
flow_set_length(byte *data, u16 len)
{
  if (len >= 0xf0)
    put_u16(data, len | 0xf000);
  else
    *data = len;
}

void
flow4_set_length(net_addr_flow4 *f, u16 len)
{
  flow_set_length(f->data, len);
}

void
flow6_set_length(net_addr_flow6 *f, u16 len)
{
  flow_set_length(f->data, len);
}



/*
 *	Flowspec iterators
 */

static const byte *
flow_first_part(const byte *data)
{
  if (!data || flow_get_length(data) == 0)
    return NULL;

  /* It is possible to encode <240 into 2 octet too */
  if ((data[0] & 0xf0) == 0xf0)
    return data + 2;

  return data + 1;
}

const byte *
flow4_first_part(const net_addr_flow4 *f)
{
  return f ? flow_first_part(f->data) : NULL;
}

const byte *
flow6_first_part(const net_addr_flow6 *f)
{
  return f ? flow_first_part(f->data) : NULL;
}



static const byte *
flow_next_part(const byte *pos, const byte *end, int ipv6)
{
  if (pos == NULL)
    bug("flow4_next_part: pos == NULL");

  switch (*pos++)
  {
  case FLOW_TYPE_DST_PREFIX:
  case FLOW_TYPE_SRC_PREFIX:
  {
    uint l = *pos++;
    uint b = (l + 7) / 8;
    if (ipv6)
    {
      uint offset = *pos++;
      pos += b - (offset + 7) / 8; /* XXX */
    }
    else
    {
      pos += b;
    }
    break;
  }

  case FLOW_TYPE_IP_PROTOCOL: /* == FLOW_TYPE_NEXT_HEADER */
  case FLOW_TYPE_PORT:
  case FLOW_TYPE_DST_PORT:
  case FLOW_TYPE_SRC_PORT:
  case FLOW_TYPE_ICMP_TYPE:
  case FLOW_TYPE_ICMP_CODE:
  case FLOW_TYPE_TCP_FLAGS:
  case FLOW_TYPE_PACKET_LENGTH:
  case FLOW_TYPE_DSCP:
  case FLOW_TYPE_FRAGMENT:
  case FLOW_TYPE_LABEL:
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

const byte *
flow4_next_part(const byte *pos, const byte *end)
{
  return flow_next_part(pos, end, 0);
}

const byte *
flow6_next_part(const byte *pos, const byte *end)
{
  return flow_next_part(pos, end, 1);
}



static struct flow_validation
flow_validate(const byte *nlri, uint len, int ipv6)
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
      return VALIDATION_STATE(FLOW_ST_BAD_TYPE_ORDER);
    type = *pos;

    switch (*pos++)
    {
    case FLOW_TYPE_DST_PREFIX:
      met_dst_pfx = 1;
      /* fall through */
    case FLOW_TYPE_SRC_PREFIX:
    {
      uint l = *pos;
      if (l > (ipv6 ? IP6_MAX_PREFIX_LENGTH : IP4_MAX_PREFIX_LENGTH))
	return VALIDATION_STATE(FLOW_ST_EXCEED_MAX_PREFIX_LENGTH);
      pos++;

      uint b = (l + 7) / 8;

      if (ipv6)
      {
        uint offset = *pos;
        if (offset > IP6_MAX_PREFIX_LENGTH)
          return VALIDATION_STATE(FLOW_ST_EXCEED_MAX_PREFIX_LENGTH);
        pos++;
        pos += b - (offset + 7) / 8; /* XXX */
      }
      else
      {
        pos += b;
      }

      break;
    }

    case FLOW_TYPE_LABEL:
      if (!ipv6)
	return VALIDATION_STATE(FLOW_ST_UNKNOWN_COMPONENT);
      /* fall through */
    case FLOW_TYPE_IP_PROTOCOL: /* == FLOW_TYPE_NEXT_HEADER */
    case FLOW_TYPE_PORT:
    case FLOW_TYPE_DST_PORT:
    case FLOW_TYPE_SRC_PORT:
    case FLOW_TYPE_ICMP_TYPE:
    case FLOW_TYPE_ICMP_CODE:
    case FLOW_TYPE_TCP_FLAGS:
    case FLOW_TYPE_PACKET_LENGTH:
    case FLOW_TYPE_DSCP:
    case FLOW_TYPE_FRAGMENT:
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
	  return VALIDATION_STATE(FLOW_ST_AND_BIT_SHOULD_BE_UNSET);

	/* This bit should be zero */
	if (*pos & 0x08)
	  return VALIDATION_STATE(FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED);

	if (type == FLOW_TYPE_TCP_FLAGS || type == FLOW_TYPE_FRAGMENT)
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
	    return VALIDATION_STATE(FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED);
	}

	/* Value length of operator */
	uint len = 1 << ((*pos & 0x30) >> 4);
	pos += 1+len;

	if (pos > end && !last)
	  return VALIDATION_STATE(FLOW_ST_NOT_COMPLETE);

	if (pos > (end+1))
	  return VALIDATION_STATE(FLOW_ST_NOT_COMPLETE);

	first = 0;
      }
      break;
    }
    default:
      return VALIDATION_STATE(FLOW_ST_UNKNOWN_COMPONENT);
    }
  }

  if (pos != end)
    return VALIDATION_STATE(FLOW_ST_NOT_COMPLETE);

  if (!ipv6 && !met_dst_pfx)
    return VALIDATION_STATE(FLOW_ST_DEST_PREFIX_REQUIRED);

  return VALIDATION_STATE(FLOW_ST_VALID);
#undef VALIDATION_STATE
}

struct flow_validation
flow4_validate(const byte *nlri, uint len)
{
  return flow_validate(nlri, len, 0);
}

struct flow_validation
flow6_validate(const byte *nlri, uint len)
{
  return flow_validate(nlri, len, 1);
}



static byte *
flow_insert_part(const byte *f_data, const byte *part, uint p_len, pool *mp, int ipv6)
{
  const u16 f_len = flow_get_length(f_data);
  const byte *f_nlri = flow_first_part(f_data);
  const byte *f_pos = f_nlri;
  const byte *f_end = f_pos + f_len - 1;
  enum flow_type p_type = *part;

  while (f_pos && (*f_pos < p_type))
  {
    if (*f_pos == p_type)
      bug("Don't try to insert a same component type more than once");

    f_pos = flow_next_part(f_pos, f_end, ipv6);
  }

  uint n_len = p_len + f_len;
  byte *n_data = mb_alloc(mp, n_len + (n_len >= 0xf0 ? 2 : 1));
  flow_set_length(n_data, n_len);

  byte *n_pos = (byte *) flow_first_part(n_data);

  if (f_pos == NULL)
  {
    /* Append */
    memcpy(n_pos, f_nlri, f_len);
    memcpy(n_pos + f_len, part, p_len);
  }
  else
  {
    /* Prepend/Insert */
    uint f_prep_size = f_pos - f_nlri;
    memcpy(n_pos, f_nlri, f_prep_size);
    memcpy(n_pos + f_prep_size, part, p_len);
    memcpy(n_pos + f_prep_size + p_len, f_pos, f_len - f_prep_size);
  }

  return n_data;
}

net_addr_flow4
flow4_insert_part(const net_addr_flow4 *f, const byte *part, uint p_len, pool *mp)
{
  net_addr_flow4 n = *f;
  n.data = flow_insert_part(f->data, part, p_len, mp, 0);

  return n;
}

net_addr_flow6
flow6_insert_part(const net_addr_flow6 *f, const byte *part, uint p_len, pool *mp)
{
  net_addr_flow6 n = *f;
  n.data = flow_insert_part(f->data, part, p_len, mp, 1);

  return n;
}
