/*
 *	BIRD Library -- Flow specification (RFC 5575) Tests
 *
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/flowspec.h"

#define NET_ADDR_FLOW4_(what,prefix,pxlen,data_)	\
  do 							\
  { 							\
    what = alloca(sizeof(net_addr_flow4) + 128);	\
    *what = NET_ADDR_FLOW4(prefix, pxlen, sizeof(data_)); \
    memcpy(what->data, &(data_), sizeof(data_));	\
  } while(0)

#define NET_ADDR_FLOW6_(what,prefix,pxlen,data_)	\
  do							\
  {							\
    what = alloca(sizeof(net_addr_flow6) + 128);	\
    *what = NET_ADDR_FLOW6(prefix, pxlen, sizeof(data_)); \
    memcpy(what->data, &(data_), sizeof(data_));	\
  } while(0)

static int
t_read_length(void)
{
  byte data[] = { 0xcc, 0xcc, 0xcc };

  u16 get;
  u16 expect;

  for (uint expect = 0; expect < 0xf0; expect++)
  {
    *data = expect;
    get = flow_read_length(data);
    bt_assert_msg(get == expect, "Testing get length 0x%02x (get 0x%02x)", expect, get);
  }

  for (uint expect = 0; expect <= 0xfff; expect++)
  {
    put_u16(data, expect | 0xf000);
    get = flow_read_length(data);
    bt_assert_msg(get == expect, "Testing get length 0x%03x (get 0x%03x)", expect, get);
  }

  return BT_SUCCESS;
}

static int
t_write_length(void)
{
  byte data[] = { 0xcc, 0xcc, 0xcc };
  uint offset;
  byte *c;

  for (uint expect = 0; expect <= 0xfff; expect++)
  {
    offset = flow_write_length(data, expect);

    uint set = (expect < 0xf0) ? *data : (get_u16(data) & 0x0fff);
    bt_assert_msg(set == expect, "Testing set length 0x%03x (set 0x%03x)", expect, set);
    bt_assert(offset == (expect < 0xf0 ? 1 : 2));
  }

  return BT_SUCCESS;
}

static int
t_first_part(void)
{
  net_addr_flow4 *f;
  NET_ADDR_FLOW4_(f, ip4_build(10,0,0,1), 24, ((byte[]) { 0x00, 0x00, 0xab }));

  const byte const *under240 = &f->data[1];
  const byte const *above240 = &f->data[2];

  /* Case 0x00 0x00 */
  bt_assert(flow4_first_part(f) == NULL);

  /* Case 0x01 0x00 */
  f->data[0] = 0x01;
  bt_assert(flow4_first_part(f) == under240);

  /* Case 0xef 0x00 */
  f->data[0] = 0xef;
  bt_assert(flow4_first_part(f) == under240);

  /* Case 0xf0 0x00 */
  f->data[0] = 0xf0;
  bt_assert(flow4_first_part(f) == NULL);

  /* Case 0xf0 0x01 */
  f->data[1] = 0x01;
  bt_assert(flow4_first_part(f) == above240);

  /* Case 0xff 0xff */
  f->data[0] = 0xff;
  f->data[1] = 0xff;
  bt_assert(flow4_first_part(f) == above240);

  return BT_SUCCESS;
}

static int
t_iterators4(void)
{
  net_addr_flow4 *f;
  NET_ADDR_FLOW4_(f, ip4_build(5,6,7,0), 24, ((byte[]) {
    25, /* Length */
    FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
    FLOW_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
    FLOW_TYPE_IP_PROTOCOL, 0x81, 0x06,
    FLOW_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOW_TYPE_TCP_FLAGS, 0x80, 0x55,
  }));

  const byte *start		= f->data;
  const byte *p1_dst_pfx	= &f->data[1];
  const byte *p2_src_pfx 	= &f->data[6];
  const byte *p3_ip_proto 	= &f->data[12];
  const byte *p4_port 		= &f->data[15];
  const byte *p5_tcp_flags 	= &f->data[23];
  const byte *end 		= &f->data[25];

  bt_assert(flow_read_length(f->data) == (end-start));
  bt_assert(flow4_first_part(f) == p1_dst_pfx);

  bt_assert(flow4_next_part(p1_dst_pfx, end) == p2_src_pfx);
  bt_assert(flow4_next_part(p2_src_pfx, end) == p3_ip_proto);
  bt_assert(flow4_next_part(p3_ip_proto, end) == p4_port);
  bt_assert(flow4_next_part(p4_port, end) == p5_tcp_flags);
  bt_assert(flow4_next_part(p5_tcp_flags, end) == NULL);

  return BT_SUCCESS;
}

static int
t_iterators6(void)
{
  net_addr_flow6 *f;
  NET_ADDR_FLOW6_(f, ip6_build(0,0,0x12345678,0x9a000000), 64, ((byte[]) {
    26, /* Length */
    FLOW_TYPE_DST_PREFIX, 0x68, 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a,
    FLOW_TYPE_SRC_PREFIX, 0x08, 0x0, 0xc0,
    FLOW_TYPE_NEXT_HEADER, 0x81, 0x06,
    FLOW_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOW_TYPE_LABEL, 0x80, 0x55,
  }));

  const byte *start		= f->data;
  const byte *p1_dst_pfx	= &f->data[1];
  const byte *p2_src_pfx 	= &f->data[9];
  const byte *p3_next_header	= &f->data[13];
  const byte *p4_port 		= &f->data[16];
  const byte *p5_label		= &f->data[24];
  const byte *end 		= &f->data[26];

  bt_assert(flow_read_length(f->data) == (end-start));
  bt_assert(flow6_first_part(f) == p1_dst_pfx);

  bt_assert(flow6_next_part(p1_dst_pfx, end) == p2_src_pfx);
  bt_assert(flow6_next_part(p2_src_pfx, end) == p3_next_header);
  bt_assert(flow6_next_part(p3_next_header, end) == p4_port);
  bt_assert(flow6_next_part(p4_port, end) == p5_label);
  bt_assert(flow6_next_part(p5_label, end) == NULL);

  return BT_SUCCESS;
}

static int
t_validation4(void)
{
  struct flow_validation v;

  byte nlri1[] = {
    FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
    FLOW_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
    FLOW_TYPE_IP_PROTOCOL, 0x81, 0x06,
    FLOW_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOW_TYPE_TCP_FLAGS, 0x80, 0x55,
  };

  /* Isn't included destination prefix */
  v = flow4_validate(nlri1, 0);
  bt_assert(v.result == FLOW_ST_DEST_PREFIX_REQUIRED);
  v = flow4_validate(&nlri1[5], sizeof(nlri1)-5);
  bt_assert(v.result == FLOW_ST_DEST_PREFIX_REQUIRED);

  /* Valid / Not Complete testing */
  uint valid_sizes[] = {5, 11, 14, 22, 25, 0};
  uint valid_idx = 0;
  for (uint size = 1; size <= sizeof(nlri1); size++)
  {
    v = flow4_validate(nlri1, size);
    bt_debug("size %u, result: %s\n", size, flow_state_str(v.result));
    if (size == valid_sizes[valid_idx])
    {
      valid_idx++;
      bt_assert(v.result == FLOW_ST_VALID);
    }
    else
    {
      bt_assert(v.result == FLOW_ST_NOT_COMPLETE);
    }
  }

  /* Misc err tests */
  struct {
    char *description;
    enum flow_state expect;
    byte nlri[1024]; /* Use strlen() for length, so please don't use null bytes. */
  } tset[] = {
    {
      .description = "33-length IPv4 prefix",
      .nlri = {
	FLOW_TYPE_DST_PREFIX, 33, 5, 6, 7, 8, 9,
      },
      .expect = FLOW_ST_EXCEED_MAX_PREFIX_LENGTH,
    },
    {
      .description = "Bad flowspec component type order",
      .nlri = {
	FLOW_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
	FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
      },
      .expect = FLOW_ST_BAD_TYPE_ORDER,
    },
    {
      .description = "Doubled destination prefix component",
      .nlri = {
	FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
	FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
      },
      .expect = FLOW_ST_BAD_TYPE_ORDER
    },
    {
      .description = "The first numeric operator has set the AND bit",
      .nlri = {
	FLOW_TYPE_PORT, 0x43, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
      },
      .expect = FLOW_ST_AND_BIT_SHOULD_BE_UNSET,
    },
    {
      .description = "Set zero bit in operand to one",
      .nlri = {
	FLOW_TYPE_IP_PROTOCOL, 0x89, 0x06,
      },
      .expect = FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED,
    },
    {
      .description = "Unknown component of type number 13",
      .nlri = {
	FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
	FLOW_TYPE_TCP_FLAGS, 0x80, 0x55,
	13 /*something new*/, 0x80, 0x55,
      },
      .expect = FLOW_ST_UNKNOWN_COMPONENT,
    }
  };

  for(uint tcase = 0; tcase < ARRAY_SIZE(tset); tcase++)
  {
    v = flow4_validate(tset[tcase].nlri, strlen(tset[tcase].nlri));
    bt_assert_msg(v.result == tset[tcase].expect, "Assertion (%s == %s) %s", flow_state_str(v.result), flow_state_str(tset[tcase].expect), tset[tcase].description);
  }

  return BT_SUCCESS;
}

static int
t_validation6(void)
{
  struct flow_validation v;

  byte nlri1[] = {
    FLOW_TYPE_DST_PREFIX, 0x68, 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a,
    FLOW_TYPE_SRC_PREFIX, 0x08, 0x0, 0xc0,
    FLOW_TYPE_NEXT_HEADER, 0x81, 0x06,
    FLOW_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOW_TYPE_LABEL, 0x80, 0x55,
  };

  /* Isn't included destination prefix */
  v = flow6_validate(nlri1, 0);
  bt_assert(v.result == FLOW_ST_VALID);

  /* Valid / Not Complete testing */
  uint valid_sizes[] = {0, 8, 12, 15, 23, 26, 0};
  uint valid_idx = 0;
  for (uint size = 0; size <= sizeof(nlri1); size++)
  {
    v = flow6_validate(nlri1, size);
    bt_debug("size %u, result: %s\n", size, flow_state_str(v.result));
    if (size == valid_sizes[valid_idx])
    {
      valid_idx++;
      bt_assert(v.result == FLOW_ST_VALID);
    }
    else
    {
      bt_assert(v.result == FLOW_ST_NOT_COMPLETE);
    }
  }

  /* Misc err tests */
  struct {
    char *description;
    enum flow_state expect;
    byte nlri[1024]; /* Use strlen() for length, so please don't use null bytes. */
  } tset[] = {
    {
      .description = "129-length IPv6 prefix",
      .nlri = {
	FLOW_TYPE_DST_PREFIX, 129, 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a,
      },
      .expect = FLOW_ST_EXCEED_MAX_PREFIX_LENGTH,
    },
    {
      .description = "Bad flowspec component type order",
      .nlri = {
	FLOW_TYPE_SRC_PREFIX, 32, 24, 13,
	FLOW_TYPE_DST_PREFIX, 24, 16, 5,
      },
      .expect = FLOW_ST_BAD_TYPE_ORDER,
    },
    {
      .description = "Doubled destination prefix component",
      .nlri = {
	FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
	FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
      },
      .expect = FLOW_ST_BAD_TYPE_ORDER
    },
    {
      .description = "The first numeric operator has set the AND bit",
      .nlri = {
	FLOW_TYPE_PORT, 0x43, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
      },
      .expect = FLOW_ST_AND_BIT_SHOULD_BE_UNSET,
    },
    {
      .description = "Set zero bit in operand to one",
      .nlri = {
	FLOW_TYPE_IP_PROTOCOL, 0x89, 0x06,
      },
      .expect = FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED,
    },
    {
      .description = "Component of type number 13 (Label) is well-known in IPv6",
      .nlri = {
	FLOW_TYPE_DST_PREFIX, 32, 8, 5, 6, 7,
	FLOW_TYPE_TCP_FLAGS, 0x80, 0x55,
	FLOW_TYPE_LABEL, 0x80, 0x55,
      },
      .expect = FLOW_ST_VALID,
    },
    {
      .description = "Unknown component of type number 14",
      .nlri = {
	FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
	FLOW_TYPE_TCP_FLAGS, 0x80, 0x55,
	14 /*something new*/, 0x80, 0x55,
      },
      .expect = FLOW_ST_UNKNOWN_COMPONENT,
    }
  };

  for(uint tcase = 0; tcase < ARRAY_SIZE(tset); tcase++)
  {
    v = flow6_validate(tset[tcase].nlri, strlen(tset[tcase].nlri));
    bt_assert_msg(v.result == tset[tcase].expect, "Assertion (%s == %s) %s", flow_state_str(v.result), flow_state_str(tset[tcase].expect), tset[tcase].description);
  }

  return BT_SUCCESS;
}

static int
t_insert4(void)
{
  resource_init();

#define SIZE 25
#define LINE1 FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7
#define LINE2 FLOW_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13
#define LINE3 FLOW_TYPE_IP_PROTOCOL, 0x81, 0x06
#define LINE4 FLOW_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90
#define LINE5 FLOW_TYPE_TCP_FLAGS, 0x80, 0x55

  const byte expect[] = { SIZE, LINE1, LINE2, LINE3, LINE4, LINE5 };

  byte p1[] = { LINE1 };
  byte p2[] = { LINE2 };
  byte p3[] = { LINE3 };
  byte p4[] = { LINE4 };
  byte p5[] = { LINE5 };

  ip4_addr ip = ip4_build(5,6,7,0);
  net_addr_flow4 *f1, *f2, *f3, *f4, *f5;
  NET_ADDR_FLOW4_(f1, ip, 24, ((byte[]) { SIZE - sizeof(p1), LINE2, LINE3, LINE4, LINE5 }));
  NET_ADDR_FLOW4_(f2, ip, 24, ((byte[]) { SIZE - sizeof(p2), LINE1, LINE3, LINE4, LINE5 }));
  NET_ADDR_FLOW4_(f3, ip, 24, ((byte[]) { SIZE - sizeof(p3), LINE1, LINE2, LINE4, LINE5 }));
  NET_ADDR_FLOW4_(f4, ip, 24, ((byte[]) { SIZE - sizeof(p4), LINE1, LINE2, LINE3, LINE5 }));
  NET_ADDR_FLOW4_(f5, ip, 24, ((byte[]) { SIZE - sizeof(p5), LINE1, LINE2, LINE3, LINE4 }));

#undef SIZE
#undef LINE1
#undef LINE2
#undef LINE3
#undef LINE4
#undef LINE5

  flow4_insert_part(f1, p1, sizeof(p1));
  flow4_insert_part(f2, p2, sizeof(p2));
  flow4_insert_part(f3, p3, sizeof(p3));
  flow4_insert_part(f4, p4, sizeof(p4));
  flow4_insert_part(f5, p5, sizeof(p5));

  bt_assert(memcmp(f1->data, expect, sizeof(expect)) == 0);
  bt_assert(memcmp(f2->data, expect, sizeof(expect)) == 0);
  bt_assert(memcmp(f3->data, expect, sizeof(expect)) == 0);
  bt_assert(memcmp(f4->data, expect, sizeof(expect)) == 0);
  bt_assert(memcmp(f5->data, expect, sizeof(expect)) == 0);

  /* From empty block */
  net_addr_flow4 *empty;
  NET_ADDR_FLOW4_(empty, ip4_build(5,6,7,0), 24, ((byte[]) {}));

  flow4_insert_part(empty, p1, sizeof(p1));
  flow4_insert_part(empty, p2, sizeof(p2));
  flow4_insert_part(empty, p3, sizeof(p3));
  flow4_insert_part(empty, p4, sizeof(p4));
  flow4_insert_part(empty, p5, sizeof(p5));
  bt_assert(memcmp(empty->data, expect, sizeof(expect)) == 0);

  return BT_SUCCESS;
}

static int
t_insert6(void)
{
  resource_init();

#define SIZE  26
#define LINE1 FLOW_TYPE_DST_PREFIX, 0x68, 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a
#define LINE2 FLOW_TYPE_SRC_PREFIX, 0x08, 0x0, 0xc0
#define LINE3 FLOW_TYPE_NEXT_HEADER, 0x81, 0x06
#define LINE4 FLOW_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90
#define LINE5 FLOW_TYPE_LABEL, 0x80, 0x55

  byte expect[] = { SIZE, LINE1, LINE2, LINE3, LINE4, LINE5 };

  byte p1[] = { LINE1 };
  byte p2[] = { LINE2 };
  byte p3[] = { LINE3 };
  byte p4[] = { LINE4 };
  byte p5[] = { LINE5 };

  ip6_addr ip = ip6_build(0x01234567, 0x89abcdef, 0, 0);

  net_addr_flow6 *f1, *f2, *f3, *f4, *f5;
  NET_ADDR_FLOW6_(f1, ip, 64, ((byte[]) { SIZE - sizeof(p1), LINE2, LINE3, LINE4, LINE5 }));
  NET_ADDR_FLOW6_(f2, ip, 64, ((byte[]) { SIZE - sizeof(p2), LINE1, LINE3, LINE4, LINE5 }));
  NET_ADDR_FLOW6_(f3, ip, 64, ((byte[]) { SIZE - sizeof(p3), LINE1, LINE2, LINE4, LINE5 }));
  NET_ADDR_FLOW6_(f4, ip, 64, ((byte[]) { SIZE - sizeof(p4), LINE1, LINE2, LINE3, LINE5 }));
  NET_ADDR_FLOW6_(f5, ip, 64, ((byte[]) { SIZE - sizeof(p5), LINE1, LINE2, LINE3, LINE4 }));

#undef SIZE
#undef LINE1
#undef LINE2
#undef LINE3
#undef LINE4
#undef LINE5

  flow6_insert_part(f1, p1, sizeof(p1));
  flow6_insert_part(f2, p2, sizeof(p2));
  flow6_insert_part(f3, p3, sizeof(p3));
  flow6_insert_part(f4, p4, sizeof(p4));
  flow6_insert_part(f5, p5, sizeof(p5));

  bt_assert(memcmp(f1->data, expect, sizeof(expect)) == 0);
  bt_assert(memcmp(f2->data, expect, sizeof(expect)) == 0);
  bt_assert(memcmp(f3->data, expect, sizeof(expect)) == 0);
  bt_assert(memcmp(f4->data, expect, sizeof(expect)) == 0);
  bt_assert(memcmp(f5->data, expect, sizeof(expect)) == 0);

  /* From empty block */
  net_addr_flow6 *empty;
  NET_ADDR_FLOW6_(empty, ip, 64, (byte[]) {});

  flow6_insert_part(empty, p1, sizeof(p1));
  flow6_insert_part(empty, p2, sizeof(p2));
  flow6_insert_part(empty, p3, sizeof(p3));
  flow6_insert_part(empty, p4, sizeof(p4));
  flow6_insert_part(empty, p5, sizeof(p5));
  bt_assert(memcmp(empty->data, expect, sizeof(expect)) == 0);

  return BT_SUCCESS;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_read_length,  "Testing get NLRI length");
  bt_test_suite(t_write_length, "Testing set NLRI length");
  bt_test_suite(t_first_part,   "Searching first part in net_addr_flow");
  bt_test_suite(t_iterators4,   "Testing iterators (IPv4)");
  bt_test_suite(t_iterators6,   "Testing iterators (IPv6)");
  bt_test_suite(t_validation4,  "Testing validation (IPv4)");
  bt_test_suite(t_validation6,  "Testing validation (IPv6)");
  bt_test_suite(t_insert4,      "Inserting components into existing Flow Specification (IPv4)");
  bt_test_suite(t_insert6,      "Inserting components into existing Flow Specification (IPv6)");

  return bt_exit_value();
}
