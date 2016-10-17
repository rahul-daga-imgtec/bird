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
test_length(void *out_, const void *in_, const void *expected_out_)
{
  int *out = out_;
  const byte *in = in_;
  const u16 *expected_out = expected_out_;

  *out = fsc_get_length(in);

  return (*out == *expected_out) ? BT_SUCCESS : BT_FAILURE;
}

static void
bt_fmt_nlri(char *buf, size_t size, const void *data)
{
  byte *start = data;
  byte *c = start;
  byte *end = start + 1;

  *buf = '\0';

  while (c <= end)
  {
    snprintf(buf+strlen(buf), size-strlen(buf), "0x%02x", *c);
    c++;
    if (c <= end)
      snprintf(buf+strlen(buf), size-strlen(buf), " ", *c);
  }
}

static int
t_length(void)
{
  struct bt_pair test_vectors[] = {
    {
      .in  = & (byte[2]) { (byte)0xff, (byte)0xff },
      .out = & (const uint) { 0xfff },
    },
    {
      .in  = & (byte[2]) { (byte)0xfa, (byte)0xbc },
      .out = & (const uint) { 0xabc },
    },
    {
      .in  = (byte [2]) { 0x0f, 0xcc },
      .out = & (const uint) { 0x0f },
    },
    {
      .in  = (byte [2]) { 0xef, 0xcc },
      .out = & (const uint) { 0xef },
    },
    {
      .in  = (byte [2]) { 0x00, 0xcc },
      .out = & (const uint) { 0x00 },
    },
  };

  return bt_assert_batch(test_vectors, test_length, bt_fmt_nlri, bt_fmt_unsigned);
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_length, "Testing NLRI length");

  return bt_exit_value();
}
