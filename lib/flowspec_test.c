/*
 *	BIRD Library -- Flow specification (RFC 5575) Tests
 *
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/flowspec.h"

static int
test_get_length(void *out_, const void *in_, const void *expected_out_)
{
  int *out = out_;
  const byte *in = in_;
  const u16 *expected_out = expected_out_;

  *out = flow_get_length(in);

  return (*out == *expected_out) ? BT_SUCCESS : BT_FAILURE;
}

static void
fmt_nlri_base(char *buf, size_t size, const byte *start, const byte *end)
{
  const byte *c = start;

  *buf = '\0';

  while (c <= end)
  {
    snprintf(buf+strlen(buf), size-strlen(buf), "0x%02x", *c);
    c++;
    if (c <= end)
      snprintf(buf+strlen(buf), size-strlen(buf), " ");
  }
}

static void
fmt_nlri2(char *buf, size_t size, const void *data)
{
  const byte *start = data;
  fmt_nlri_base(buf, size, data, start + 1);
}

static int
t_get_length(void)
{
  struct bt_pair test_vectors[] = {
    {
      .in  = & (byte[]) { 0xff, 0xff, 0x0f, 0xcc, 0xcc, 0xcc },
      .out = & (const uint) { 0xfff },
    },
    {
      .in  = & (byte[]) { 0xfa, 0xbc },
      .out = & (const uint) { 0xabc },
    },
    {
      .in  = & (byte []) { 0x0f, 0xcc, 0xcc, 0xcc },
      .out = & (const uint) { 0x0f },
    },
    {
      .in  = & (byte []) { 0xef, 0xcc },
      .out = & (const uint) { 0xef },
    },
    {
      .in  = & (byte []) { 0x00, 0xcc },
      .out = & (const uint) { 0x00 },
    },
  };

  return bt_assert_batch(test_vectors, test_get_length, fmt_nlri2, bt_fmt_unsigned);
}

static int
t_set_length(void)
{
  byte sb[100];
  byte *c;

  for (uint i = 0; i < 240; i++)
  {
    c = flow_set_length(sb, i);
    bt_assert(c == sb+1);
    bt_assert(*sb == i);
    bt_assert(i == flow_get_length(sb));
  }

  for (uint i = 240; i <= 0xfff; i++)
  {
    c = flow_set_length(sb, i);
    bt_assert(c == sb+2);
    bt_assert((get_u16(sb) & 0x0fff) == i);
    bt_assert(i == flow_get_length(sb));
  }

  return BT_SUCCESS;
}

static int
t_first_part(void)
{
  net_addr_flow4 f = NET_ADDR_FLOW4(ip4_build(10,0,0,1), 24, ((byte[]) { 0x00, 0x00, 0xab }));
  const byte const *under240 = &f.data[1];
  const byte const *above240 = &f.data[2];

  /* Case 0x00 0x00 */
  bt_assert(flow_first_part(&f) == NULL);

  /* Case 0x01 0x00 */
  f.data[0] = 0x01;
  bt_assert(flow_first_part(&f) == under240);

  /* Case 0xef 0x00 */
  f.data[0] = 0xef;
  bt_assert(flow_first_part(&f) == under240);

  /* Case 0xf0 0x00 */
  f.data[0] = 0xf0;
  bt_assert(flow_first_part(&f) == NULL);

  /* Case 0xf0 0x01 */
  f.data[1] = 0x01;
  bt_assert(flow_first_part(&f) == above240);

  /* Case 0xff 0xff */
  f.data[0] = 0xff;
  f.data[1] = 0xff;
  bt_assert(flow_first_part(&f) == above240);

  return BT_SUCCESS;
}

static int
t_iterators(void)
{
  net_addr_flow4 f = NET_ADDR_FLOW4(ip4_build(5,6,7,0), 24, ((byte[]) {
    25, /* Length */
    FLOWS_TYPE_DST_PREFIX, 24, 5, 6, 7,
    FLOWS_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
    FLOWS_TYPE_IP_PROTOCOL, 0x81, 0x06,
    FLOWS_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOWS_TYPE_TCP_FLAGS, 0x80, 0x55,
  }));

  const byte *start		= f.data;
  const byte *p1_dst_pfx	= &f.data[1];
  const byte *p2_src_pfx 	= &f.data[6];
  const byte *p3_ip_proto 	= &f.data[12];
  const byte *p4_port 		= &f.data[15];
  const byte *p5_tcp_flags 	= &f.data[23];
  const byte *end 		= &f.data[25];

  bt_assert(flow_get_length(start) == (end-start));
  bt_assert(flow_first_part(&f) == p1_dst_pfx);

  bt_assert(flow4_next_part(p1_dst_pfx, end) == p2_src_pfx);
  bt_assert(flow4_next_part(p2_src_pfx, end) == p3_ip_proto);
  bt_assert(flow4_next_part(p3_ip_proto, end) == p4_port);
  bt_assert(flow4_next_part(p4_port, end) == p5_tcp_flags);
  bt_assert(flow4_next_part(p5_tcp_flags, end) == NULL);

  return BT_SUCCESS;
}

static int
t_validation(void)
{
  struct flow_validation v;

  byte nlri1[] = {
    FLOWS_TYPE_DST_PREFIX, 24, 5, 6, 7,
    FLOWS_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
    FLOWS_TYPE_IP_PROTOCOL, 0x81, 0x06,
    FLOWS_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOWS_TYPE_TCP_FLAGS, 0x80, 0x55,
  };

  /* Isn't included destination prefix */
  v = flow4_validate(nlri1, 0);
  bt_assert(v.result == FLOW_DIDNT_MEET_DEST_PREFIX);
  v = flow4_validate(&nlri1[5], sizeof(nlri1)-5);
  bt_assert(v.result == FLOW_DIDNT_MEET_DEST_PREFIX);

  /* Valid / Not Complete testing*/
  uint valid_sizes[] = {5, 11, 14, 22, 25, 0};
  uint valid_idx = 0;
  for (uint size = 1; size <= sizeof(nlri1); size++)
  {
    v = flow4_validate(nlri1, size);
    bt_debug("size %u, result: %s\n", size, flow_err_str(v.result));
    if (size == valid_sizes[valid_idx])
    {
      valid_idx++;
      bt_assert(v.result == FLOW_VALID);
    }
    else
    {
      bt_assert(v.result == FLOW_NOT_COMPLETE);
    }
  }

  /* Misc err tests */
  struct {
    char *description;
    enum flow_err expect;
    byte nlri[1024]; /* Use strlen() for length, so please don't use null bytes. */
  } tset[] = {
    {
      .description = "33-length IPv4 prefix",
      .nlri = {
	FLOWS_TYPE_DST_PREFIX, 33, 5, 6, 7, 8, 9,
      },
      .expect = FLOW_EXCEED_MAX_PREFIX_LENGTH,
    },
    {
      .description = "Bad flowspec component type order",
      .nlri = {
	FLOWS_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
	FLOWS_TYPE_DST_PREFIX, 24, 5, 6, 7,
      },
      .expect = FLOW_BAD_TYPE_ORDER,
    },
    {
      .description = "Doubled destination prefix component",
      .nlri = {
	FLOWS_TYPE_DST_PREFIX, 24, 5, 6, 7,
	FLOWS_TYPE_DST_PREFIX, 24, 5, 6, 7,
      },
      .expect = FLOW_BAD_TYPE_ORDER
    },
    {
      .description = "The first numeric operator has set the AND bit",
      .nlri = {
	FLOWS_TYPE_PORT, 0x43, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
      },
      .expect = FLOW_AND_BIT_SHOULD_BE_UNSET,
    },
    {
      .description = "Set zero bit in operand to one",
      .nlri = {
	FLOWS_TYPE_IP_PROTOCOL, 0x89, 0x06,
      },
      .expect = FLOW_ZERO_BIT_SHOULD_BE_UNSED,
    },
    {
      .description = "Unknown component of type number 13",
      .nlri = {
	FLOWS_TYPE_DST_PREFIX, 24, 5, 6, 7,
	FLOWS_TYPE_TCP_FLAGS, 0x80, 0x55,
	13 /*something new*/, 0x80, 0x55,
      },
      .expect = FLOW_UNKNOWN_COMPONENT,
    }
  };

  for(uint tcase = 0; tcase < ARRAY_SIZE(tset); tcase++)
  {
    v = flow4_validate(tset[tcase].nlri, strlen(tset[tcase].nlri));
    bt_assert_msg(v.result == tset[tcase].expect, "Assertion (%s == %s) %s", flow_err_str(v.result), flow_err_str(tset[tcase].expect), tset[tcase].description);
  }

  return BT_SUCCESS;
}

static int
t_insert(void)
{
  net_addr_flow4 new;
  resource_init();

  byte expect[] = {
    25,
    FLOWS_TYPE_DST_PREFIX, 24, 5, 6, 7,
    FLOWS_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
    FLOWS_TYPE_IP_PROTOCOL, 0x81, 0x06,
    FLOWS_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOWS_TYPE_TCP_FLAGS, 0x80, 0x55,
  };

  byte p1[] = { FLOWS_TYPE_DST_PREFIX, 24, 5, 6, 7, };
  byte p2[] = { FLOWS_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13, };
  byte p3[] = { FLOWS_TYPE_IP_PROTOCOL, 0x81, 0x06, };
  byte p4[] = { FLOWS_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90, };
  byte p5[] = { FLOWS_TYPE_TCP_FLAGS, 0x80, 0x55, };

  net_addr_flow4 f1 = NET_ADDR_FLOW4(ip4_build(5,6,7,0), 24, ((byte[]) {
    25 - sizeof(p1),
/*  FLOWS_TYPE_DST_PREFIX, 24, 5, 6, 7,  */
    FLOWS_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
    FLOWS_TYPE_IP_PROTOCOL, 0x81, 0x06,
    FLOWS_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOWS_TYPE_TCP_FLAGS, 0x80, 0x55,
  }));
  net_addr_flow4 f2 = NET_ADDR_FLOW4(ip4_build(5,6,7,0), 24, ((byte[]) {
    25 - sizeof(p2),
    FLOWS_TYPE_DST_PREFIX, 24, 5, 6, 7,
/*  FLOWS_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13, */
    FLOWS_TYPE_IP_PROTOCOL, 0x81, 0x06,
    FLOWS_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOWS_TYPE_TCP_FLAGS, 0x80, 0x55,
  }));
  net_addr_flow4 f3 = NET_ADDR_FLOW4(ip4_build(5,6,7,0), 24, ((byte[]) {
    25 - sizeof(p3),
    FLOWS_TYPE_DST_PREFIX, 24, 5, 6, 7,
    FLOWS_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
/*  FLOWS_TYPE_IP_PROTOCOL, 0x81, 0x06,  */
    FLOWS_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOWS_TYPE_TCP_FLAGS, 0x80, 0x55,
  }));
  net_addr_flow4 f4 = NET_ADDR_FLOW4(ip4_build(5,6,7,0), 24, ((byte[]) {
    25 - sizeof(p4),
    FLOWS_TYPE_DST_PREFIX, 24, 5, 6, 7,
    FLOWS_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
    FLOWS_TYPE_IP_PROTOCOL, 0x81, 0x06,
/*  FLOWS_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90, */
    FLOWS_TYPE_TCP_FLAGS, 0x80, 0x55,
  }));
  net_addr_flow4 f5 = NET_ADDR_FLOW4(ip4_build(5,6,7,0), 24, ((byte[]) {
    25 - sizeof(p5),
    FLOWS_TYPE_DST_PREFIX, 24, 5, 6, 7,
    FLOWS_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
    FLOWS_TYPE_IP_PROTOCOL, 0x81, 0x06,
    FLOWS_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
/*  FLOWS_TYPE_TCP_FLAGS, 0x80, 0x55, */
  }));

  new = flow_insert_part(&f1, p1, sizeof(p1), &root_pool);
  bt_assert(memcmp(new.data, expect, sizeof(expect)) == 0);

  new = flow_insert_part(&f2, p2, sizeof(p2), &root_pool);
  bt_assert(memcmp(new.data, expect, sizeof(expect)) == 0);

  new = flow_insert_part(&f3, p3, sizeof(p3), &root_pool);
  bt_assert(memcmp(new.data, expect, sizeof(expect)) == 0);

  new = flow_insert_part(&f4, p4, sizeof(p4), &root_pool);
  bt_assert(memcmp(new.data, expect, sizeof(expect)) == 0);

  new = flow_insert_part(&f5, p5, sizeof(p5), &root_pool);
  bt_assert(memcmp(new.data, expect, sizeof(expect)) == 0);

  return BT_SUCCESS;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_get_length, "Testing get NLRI length");
  bt_test_suite(t_set_length, "Testing set NLRI length");
  bt_test_suite(t_iterators,  "Testing iterators");
  bt_test_suite(t_first_part, "Searching first part in net_addr_flow");
  bt_test_suite(t_validation, "Testing validation of IPv4 flows");
  bt_test_suite(t_insert,     "Insert a flow component into existing flow spec");

  return bt_exit_value();
}
