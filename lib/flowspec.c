/*
 *	BIRD Library -- Flow specification (RFC 5575)
 *
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/flowspec.h"
#include "conf/conf.h"

static const char* flow_validated_state_str_[] = {
  [FLOW_ST_UNKNOWN_COMPONENT] 		= "Unknown component",
  [FLOW_ST_VALID] 			= "Valid",
  [FLOW_ST_NOT_COMPLETE] 		= "Not complete",
  [FLOW_ST_EXCEED_MAX_PREFIX_LENGTH] 	= "Exceed maximal prefix length",
  [FLOW_ST_EXCEED_MAX_VALUE_LENGTH]	= "Exceed maximal value length",
  [FLOW_ST_BAD_TYPE_ORDER] 		= "Bad component order",
  [FLOW_ST_AND_BIT_SHOULD_BE_UNSET] 	= "The AND-bit should be unset",
  [FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED] 	= "The Zero-bit should be unset",
  [FLOW_ST_DEST_PREFIX_REQUIRED] 	= "Destination prefix is required to define"
};

const char *
flow_validated_state_str(enum flow_validated_state code)
{
  return flow_validated_state_str_[code];
}

static const char* flow4_type_str[] = {
  [FLOW_TYPE_DST_PREFIX]		= "dst",
  [FLOW_TYPE_SRC_PREFIX]		= "src",
  [FLOW_TYPE_IP_PROTOCOL]		= "proto",
  [FLOW_TYPE_PORT]			= "port",
  [FLOW_TYPE_DST_PORT]			= "dport",
  [FLOW_TYPE_SRC_PORT]			= "sport",
  [FLOW_TYPE_ICMP_TYPE]			= "icmp type",
  [FLOW_TYPE_ICMP_CODE]			= "icmp code",
  [FLOW_TYPE_TCP_FLAGS]			= "tcp flags",
  [FLOW_TYPE_PACKET_LENGTH]		= "length",
  [FLOW_TYPE_DSCP]			= "dscp",
  [FLOW_TYPE_FRAGMENT]			= "fragment"
};

static const char* flow6_type_str[] = {
  [FLOW_TYPE_DST_PREFIX]		= "dst",
  [FLOW_TYPE_SRC_PREFIX]		= "src",
  [FLOW_TYPE_NEXT_HEADER]		= "next header",
  [FLOW_TYPE_PORT]			= "port",
  [FLOW_TYPE_DST_PORT]			= "dport",
  [FLOW_TYPE_SRC_PORT]			= "sport",
  [FLOW_TYPE_ICMP_TYPE]			= "icmp type",
  [FLOW_TYPE_ICMP_CODE]			= "icmp code",
  [FLOW_TYPE_TCP_FLAGS]			= "tcp flags",
  [FLOW_TYPE_PACKET_LENGTH]		= "length",
  [FLOW_TYPE_DSCP]			= "dscp",
  [FLOW_TYPE_FRAGMENT]			= "fragment",
  [FLOW_TYPE_LABEL]			= "label"
};

const char *
flow_type_str(enum flow_type type, int ipv6)
{
  return ipv6 ? flow6_type_str[type] : flow4_type_str[type];
}

/**
 * flow_write_length - write compressed length value
 * @data: destination to write
 * @len: the value of the length (0 to 0xfff)
 *
 * It returns a size (offset) of written data to destination.
 */
uint
flow_write_length(byte *data, u16 len)
{
  if (len >= 0xf0)
  {
    put_u16(data, len | 0xf000);
    return 2;
  }

  *data = len;
  return 1;
}

inline static uint
get_value_length(const byte *op)
{
  return (1 << ((*op & 0x30) >> 4));
}



/*
 *	Flowspec iterators
 */

static const byte *
flow_first_part(const byte *data)
{
  if (!data || flow_read_length(data) == 0)
    return NULL;

  /* It is possible to encode <240 into 2 octet too */
  if ((data[0] & 0xf0) == 0xf0)
    return data + 2;

  return data + 1;
}

inline const byte *
flow4_first_part(const net_addr_flow4 *f)
{
  return f ? flow_first_part(f->data) : NULL;
}

inline const byte *
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
    uint pxlen = *pos++;
    uint bytes = BYTES(pxlen);
    if (ipv6)
    {
      uint pxoffset = *pos++;
      pos += bytes - BYTES(pxoffset);
    }
    else
    {
      pos += bytes;
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
      uint len = get_value_length(pos);
      pos += 1+len;
    }
    break;
  }
  default:
    return NULL;
  }

  return (pos < end) ? pos : NULL;
}

inline const byte *
flow4_next_part(const byte *pos, const byte *end)
{
  return flow_next_part(pos, end, 0);
}

inline const byte *
flow6_next_part(const byte *pos, const byte *end)
{
  return flow_next_part(pos, end, 1);
}


/*
 * 	Flowspec validation
 */

static const u8 flow4_max_value_length[] = {
  [FLOW_TYPE_DST_PREFIX]		= 0,
  [FLOW_TYPE_SRC_PREFIX]		= 0,
  [FLOW_TYPE_IP_PROTOCOL]		= 1,
  [FLOW_TYPE_PORT]			= 2,
  [FLOW_TYPE_DST_PORT]			= 2,
  [FLOW_TYPE_SRC_PORT]			= 2,
  [FLOW_TYPE_ICMP_TYPE]			= 1,
  [FLOW_TYPE_ICMP_CODE]			= 1,
  [FLOW_TYPE_TCP_FLAGS]			= 2,
  [FLOW_TYPE_PACKET_LENGTH]		= 2,
  [FLOW_TYPE_DSCP]			= 1,
  [FLOW_TYPE_FRAGMENT]			= 2
};

static const u8 flow6_max_value_length[] = {
  [FLOW_TYPE_DST_PREFIX]		= 0,
  [FLOW_TYPE_SRC_PREFIX]		= 0,
  [FLOW_TYPE_NEXT_HEADER]		= 1,
  [FLOW_TYPE_PORT]			= 2,
  [FLOW_TYPE_DST_PORT]			= 2,
  [FLOW_TYPE_SRC_PORT]			= 2,
  [FLOW_TYPE_ICMP_TYPE]			= 1,
  [FLOW_TYPE_ICMP_CODE]			= 1,
  [FLOW_TYPE_TCP_FLAGS]			= 2,
  [FLOW_TYPE_PACKET_LENGTH]		= 2,
  [FLOW_TYPE_DSCP]			= 1,
  [FLOW_TYPE_FRAGMENT]			= 2,
  [FLOW_TYPE_LABEL]			= 4
};

static u8
flow_max_value_length(enum flow_type type, int ipv6)
{
  return ipv6 ? flow6_max_value_length[type] : flow4_max_value_length[type];
}

void
flow_check_cf_bmk_values(struct flow_builder *fb, u32 val, u32 mask)
{
  flow_check_cf_value_length(fb, val);
  flow_check_cf_value_length(fb, mask);

  if (val & ~(u32)mask)
  {
    u32  val2 =  val ^ (val & ~mask);
    u32 mask2 = mask ^ (val & ~mask);
    cf_error("Value 0x%x outside bitmask 0x%x, did you mean 0x%x/0x%x or 0x%x/0x%x?", val, mask, val, mask2, val2, mask);
  }
}

void
flow_check_cf_value_length(struct flow_builder *fb, u32 val)
{
  enum flow_type t = fb->this_type;
  u8 max = flow_max_value_length(t, fb->ipv6);

  if (max == 1 && (val > 0xff))
    cf_error("%s value %u out of range (0-255)", flow_type_str(t, fb->ipv6), val);

  if (max == 2 && (val > 0xffff))
    cf_error("%s value %u out of range (0-65535)", flow_type_str(t, fb->ipv6), val);
}

static enum flow_validated_state
flow_validate(const byte *nlri, uint len, int ipv6)
{
  enum flow_type type = 0;
  const byte *pos = nlri;
  const byte *end = nlri + len;
  int met_dst_pfx = 0;

  while (pos < end)
  {
    /* Check increasing type ordering */
    if (*pos <= type)
      return FLOW_ST_BAD_TYPE_ORDER;
    type = *pos++;

    switch (type)
    {
    case FLOW_TYPE_DST_PREFIX:
      met_dst_pfx = 1;
      /* Fall through */
    case FLOW_TYPE_SRC_PREFIX:
    {
      uint pxlen = *pos;
      if (pxlen > (ipv6 ? IP6_MAX_PREFIX_LENGTH : IP4_MAX_PREFIX_LENGTH))
	return FLOW_ST_EXCEED_MAX_PREFIX_LENGTH;
      pos++;

      uint bytes = BYTES(pxlen);
      if (ipv6)
      {
        uint pxoffset = *pos;
        if (pxoffset > IP6_MAX_PREFIX_LENGTH || pxoffset > pxlen)
          return FLOW_ST_EXCEED_MAX_PREFIX_LENGTH;
        pos++;
        bytes -= BYTES(pxoffset);
      }
      pos += bytes;

      break;
    }

    case FLOW_TYPE_LABEL:
      if (!ipv6)
	return FLOW_ST_UNKNOWN_COMPONENT;
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
	  return FLOW_ST_AND_BIT_SHOULD_BE_UNSET;

	/* This bit should be zero */
	if (*pos & 0x08)
	  return FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED;

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
	    return FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED;
	}

	/* Value length of operator */
	uint len = get_value_length(pos);
	if (len > flow_max_value_length(type, ipv6))
	  return FLOW_ST_EXCEED_MAX_VALUE_LENGTH;
	pos += 1+len;

	if (pos > end && !last)
	  return FLOW_ST_NOT_COMPLETE;

	if (pos > (end+1))
	  return FLOW_ST_NOT_COMPLETE;

	first = 0;
      }
      break;
    }
    default:
      return FLOW_ST_UNKNOWN_COMPONENT;
    }
  }

  if (pos != end)
    return FLOW_ST_NOT_COMPLETE;

  if (!ipv6 && !met_dst_pfx)
    return FLOW_ST_DEST_PREFIX_REQUIRED;

  return FLOW_ST_VALID;
}

inline enum flow_validated_state
flow4_validate(const byte *nlri, uint len)
{
  return flow_validate(nlri, len, 0);
}

inline enum flow_validated_state
flow6_validate(const byte *nlri, uint len)
{
  return flow_validate(nlri, len, 1);
}


/*
 * 	Flowspec Builder
 */

struct flow_builder *
flow_builder_init(pool *pool)
{
  struct flow_builder *fb = mb_allocz(pool, sizeof(struct flow_builder));
  BUFFER_INIT(fb->data, pool, 4);
  return fb;
}

static int
builder_add_prepare(struct flow_builder *fb)
{
  if (fb->last_type != fb->this_type && fb->parts[fb->this_type].length)
    return 0;
  else
    if (fb->last_type != fb->this_type)
      fb->parts[fb->this_type].offset = fb->data.used;
  return 1;
}

static void
builder_add_finish(struct flow_builder *fb)
{
  fb->parts[fb->this_type].length = fb->data.used - fb->parts[fb->this_type].offset;
  flow_builder_set_type(fb, fb->this_type);
}

static void
push_pfx_to_buffer(struct flow_builder *fb, u8 pxlen, byte *ip)
{
  u8 pxlen_bytes = BYTES(pxlen);

  for (int i = 0; i < pxlen_bytes; i++)
    BUFFER_PUSH(fb->data) = *ip++;
}

int
flow_builder4_add_pfx(struct flow_builder *fb, const net_addr_ip4 *n4)
{
  if (!builder_add_prepare(fb))
    return 0;

  ip4_addr ip4 = ip4_hton(n4->prefix);

  BUFFER_PUSH(fb->data) = fb->this_type;
  BUFFER_PUSH(fb->data) = n4->pxlen;
  push_pfx_to_buffer(fb, n4->pxlen, (void *) &ip4);

  builder_add_finish(fb);
  return 1;
}

int
flow_builder6_add_pfx(struct flow_builder *fb, const net_addr_ip6 *n6, u32 pxoffset)
{
  if (!builder_add_prepare(fb))
    return 0;

  ip6_addr ip6 = ip6_hton(n6->prefix);

  BUFFER_PUSH(fb->data) = fb->this_type;
  BUFFER_PUSH(fb->data) = n6->pxlen;
  BUFFER_PUSH(fb->data) = pxoffset;
  push_pfx_to_buffer(fb, n6->pxlen - pxoffset, ((byte *) &ip6) + BYTES(pxoffset));

  builder_add_finish(fb);
  return 1;
}

int
flow_builder_add_op_val(struct flow_builder *fb, byte op, u32 value)
{
  if (!builder_add_prepare(fb))
    return 0;

  if (fb->this_type == fb->last_type)
  {
    /* Remove the end-bit from last operand-value pair of the component */
    fb->data.data[fb->last_op_offset] &= 0x7f;
  }
  else
  {
    BUFFER_PUSH(fb->data) = fb->this_type;
  }

  fb->last_op_offset = fb->data.used;

  /* Set the end-bit for operand-value pair of the component */
  op |= 0x80;

  if (value & 0xff00)
  {
    BUFFER_PUSH(fb->data) = op | 0x10;
    put_u16(BUFFER_INC(fb->data, 2), value);
  }
  else
  {
    BUFFER_PUSH(fb->data) = op;
    BUFFER_PUSH(fb->data) = (u8) value;
  }

  builder_add_finish(fb);
  return 1;
}

int
flow_builder_add_val_mask(struct flow_builder *fb, byte op, u32 value, u32 mask)
{
  u32 a =  value & mask;
  u32 b = ~value & mask;

  if (a)
  {
    flow_builder_add_op_val(fb, op | 0x01, a);
    op = 0x40;
  }

  if (b)
    flow_builder_add_op_val(fb, op | 0x02, b);

  return 1;
}

void
flow_builder_set_type(struct flow_builder *fb, enum flow_type p)
{
  fb->last_type = fb->this_type;
  fb->this_type = p;
}

static ip4_addr
flow_read_ip4(const byte *px, uint pxlen)
{
  ip4_addr ip = IP4_NONE;
  memcpy(&ip, px, BYTES(pxlen));
  return ip4_ntoh(ip);
}

static ip6_addr
flow_read_ip6(const byte *px, uint pxlen, uint pxoffset)
{
  uint floor_offset = BYTES(pxoffset - (pxoffset % 8));
  uint ceil_len = BYTES(pxlen);
  ip6_addr ip = IP6_NONE;

  memcpy(((byte *) &ip) + floor_offset, px, ceil_len - floor_offset);

  return ip6_ntoh(ip);
}

static void
builder_write_parts(struct flow_builder *fb, byte *buf)
{
  for (int i = 1; i < FLOW_TYPE_MAX; i++)
  {
    if (fb->parts[i].length)
    {
      memcpy(buf, fb->data.data + fb->parts[i].offset, fb->parts[i].length);
      buf += fb->parts[i].length;
    }
  }
}

net_addr_flow4 *
flow_builder4_finalize(struct flow_builder *fb, linpool *lpool)
{
  uint data_len =  fb->data.used + (fb->data.used < 0xf0 ? 1 : 2);
  net_addr_flow4 *n = lp_alloc(lpool, sizeof(struct net_addr_flow4) + data_len);

  ip4_addr prefix = IP4_NONE;
  uint pxlen = 0;

  if (fb->parts[FLOW_TYPE_DST_PREFIX].length)
  {
    byte *p = fb->data.data + fb->parts[FLOW_TYPE_DST_PREFIX].offset + 1;
    pxlen = *p++;
    prefix = flow_read_ip4(p, pxlen);
  }
  *n = NET_ADDR_FLOW4(prefix, pxlen, data_len);

  builder_write_parts(fb, n->data + flow_write_length(n->data, fb->data.used));

  return n;
}

net_addr_flow6 *
flow_builder6_finalize(struct flow_builder *fb, linpool *lpool)
{
  uint data_len =  fb->data.used + (fb->data.used < 0xf0 ? 1 : 2);
  net_addr_flow6 *n = lp_alloc(lpool, sizeof(net_addr_flow6) + data_len);

  ip6_addr prefix = IP6_NONE;
  uint pxlen = 0;

  if (fb->parts[FLOW_TYPE_DST_PREFIX].length)
  {
    byte *p = fb->data.data + fb->parts[FLOW_TYPE_DST_PREFIX].offset + 1;
    pxlen = *p++;
    uint pxoffset = *p++;
    prefix = flow_read_ip6(p, pxlen, pxoffset);
  }
  *n = NET_ADDR_FLOW6(prefix, pxlen, data_len);

  builder_write_parts(fb, n->data + flow_write_length(n->data, fb->data.used));

  return n;
}

void
flow_builder_clear(struct flow_builder *fb)
{
  BUFFER_FLUSH(fb->data);

  byte *data = fb->data.data;
  uint size = fb->data.size;
  uint used = fb->data.used;

  memset(fb, 0, sizeof(struct flow_builder));

  fb->data.data = data;
  fb->data.size = size;
  fb->data.used = used;
}

void
flow4_validate_cf(net_addr *n)
{
  net_addr_flow4 *n4 = (void *) n;
  enum flow_validated_state r = flow4_validate(flow4_first_part(n4), flow_read_length(n4->data));

  if (r != FLOW_ST_VALID)
    cf_error("Invalid flow route: %s", flow_validated_state_str(r));
}

void
flow6_validate_cf(net_addr *n)
{
  net_addr_flow6 *n6 = (void *) n;
  enum flow_validated_state r = flow6_validate(flow6_first_part(n6), flow_read_length(n6->data));

  if (r != FLOW_ST_VALID)
    cf_error("Invalid flow route: %s", flow_validated_state_str(r));
}


/*
 * 	Net Formatting
 */

static const char *
num_op_str(byte op)
{
  switch (op & 0x07)
  {
  case 0b000: return "true";
  case 0b001: return "=";
  case 0b010: return ">";
  case 0b011: return ">=";
  case 0b100: return "<";
  case 0b101: return "<=";
  case 0b110: return "!=";
  case 0b111: return "false";
  }
}

static const char *
logic_op_str(byte op)
{
  switch (op & 0x40)
  {
  case 0x00: return "||";
  case 0x40: return "&&";
  }
}

static u32
get_value(const byte *op)
{
  const byte *val = op + 1;

  switch (get_value_length(op))
  {
  case 1: return *val;
  case 2: return get_u16(val);
  case 4: return get_u32(val);
  }

  return 0;
}

static int
net_format_flow(char *buf, uint blen, const byte *data, uint dlen, int ipv6)
{
#define PRINT(msg, ...)							\
  do 									\
  { 									\
     int chrs__ = bsnprintf(buf+chrs, blen-chrs, msg, ##__VA_ARGS__);	\
     if (chrs__ < 1) 							\
     { 									\
       chrs__ = MIN(chrs, blen-6);					\
       chrs += bsnprintf(buf+chrs__, blen-chrs__, " ...}");		\
       goto end;							\
     }									\
     chrs += chrs__;							\
  } while (0)

  const byte *part = flow_first_part(data);
  int chrs = 0;
  *buf = 0;

  if (ipv6)
    PRINT("flow6 { ");
  else
    PRINT("flow4 { ");

  while (part)
  {
    PRINT("%s ", flow_type_str(*part, ipv6));

    switch (*part)
    {
    case FLOW_TYPE_DST_PREFIX:
    case FLOW_TYPE_SRC_PREFIX:
    {
      uint pxlen = *(part+1);
      if (ipv6)
      {
	uint pxoffset = *(part+2);
	if (pxoffset)
	  PRINT("%I6/%u-%u; ", flow_read_ip6(part+3,pxlen,pxoffset), pxoffset, pxlen);
	else
	  PRINT("%I6/%u; ", flow_read_ip6(part+3,pxlen,0), pxlen);
      }
      else
      {
	PRINT("%I4/%u; ", flow_read_ip4(part+2,pxlen), pxlen);
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
      const byte *op = part+1;
      u32 val;
      uint len;
      uint first = 1;

      while (1)
      {
	if (!first)
	  PRINT("%s ", logic_op_str(*op));
	first = 0;

	val = get_value(op);
	len = get_value_length(op);

	if (*part == FLOW_TYPE_FRAGMENT || *part == FLOW_TYPE_TCP_FLAGS)
	{
	  /*
	   *   Not Match  Show
	   *  ------------------
	   *    0    0    !0/B
	   *    0    1     B/B
	   *    1    0     0/B
	   *    1    1    !B/B
	   */

	  if ((*op & 0x3) == 0x3 || (*op & 0x3) == 0)
	    PRINT("!");

	  PRINT("0x%x/0x%x", ((*op & 0x1) ? val : 0), val);
	}
	else
	{
	  PRINT("%s %u", num_op_str(*op), val);
	}

	/* Check End-bit */
	if ((*op & 0x80) == 0x80)
	{
	  PRINT("; ");
	  break;
	}
	else
	{
	  PRINT(" ");
	}

	op += 1 + len;
      }
    }
    }

    part = flow_next_part(part, data+dlen, ipv6);
  }

  PRINT("}");

 end:
  return chrs;

#undef PRINT
}

int
flow4_net_format(char *buf, uint blen, const net_addr_flow4 *n4)
{
  return net_format_flow(buf, blen, n4->data, n4->length - sizeof(net_addr_flow4), 0);
}

int
flow6_net_format(char *buf, uint blen, const net_addr_flow6 *n6)
{
  return net_format_flow(buf, blen, n6->data, n6->length - sizeof(net_addr_flow6), 1);
}
