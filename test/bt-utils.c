/*
 *	BIRD Test -- Utils for testing parsing configuration file
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"

#include "lib/unix.h"
#include "lib/krt.h"

#include "nest/iface.h"
#include "nest/locks.h"

#include "filter/filter.h"

#define BETWEEN(a, b, c)  (((a) >= (b)) && ((a) <= (c)))

static const byte *bt_config_parse_pos;
static uint bt_config_parse_remain_len;

static int
cf_txt_read(byte *dest_buf, uint max_len, UNUSED int fd)
{
  if (max_len > bt_config_parse_remain_len)
    max_len = bt_config_parse_remain_len;
  memcpy(dest_buf, bt_config_parse_pos, max_len);
  bt_config_parse_pos += max_len;
  bt_config_parse_remain_len -= max_len;

  return max_len;
}

void
bt_bird_init(void)
{
  if(bt_verbose)
    log_init_debug("");
  log_switch(bt_verbose != 0, NULL, NULL);

  resource_init();
  olock_init();
  io_init();
  rt_init();
  if_init();
  config_init();

  protos_build();
  proto_build(&proto_unix_kernel);
  proto_build(&proto_unix_iface);
}

static void
bt_debug_with_line_nums(const char *str)
{
  uint lino = 0;
  while (*str)
  {
    lino++;
    bt_debug("%4u    ", lino);
    do
    {
      bt_debug("%c", *str);
    } while (*str && *(str++) != '\n');
  }
  bt_debug("\n");
}

static void
bt_show_cfg_error(const char *str, const struct config *cfg)
{
  int lino = 0;
  int lino_delta = 5;
  int lino_err = cfg->err_lino;

  while (*str)
  {
    lino++;
    if (BETWEEN(lino, lino_err - lino_delta, lino_err + lino_delta))
      bt_debug("%4u%s", lino, (lino_err == lino ? " >> " : "    "));
    do
    {
      if (BETWEEN(lino, lino_err - lino_delta, lino_err + lino_delta))
	bt_debug("%c", *str);
    } while (*str && *(str++) != '\n');
  }
  bt_debug("\n");
}

struct config *
bt_config_parse(const char *cfg_str)
{
  bt_debug_with_line_nums(cfg_str);
  struct config *cfg = config_alloc("");
  bt_config_parse_pos = cfg_str;
  bt_config_parse_remain_len = strlen(cfg_str);
  cf_read_hook = cf_txt_read;

  bt_assert_msg(config_parse(cfg) == 1, "Parse configuration");

  if (cfg->err_msg)
  {
    bt_debug("Parse error at line %d: %s \n", cfg->err_lino, cfg->err_msg);
    bt_show_cfg_error(cfg_str, cfg);
  }
  else
  {
    config_commit(cfg, RECONFIG_HARD, 0);
    new_config = cfg;

    return cfg;
  }

  return NULL; /* Error in parsing */
}

uint
naive_pow(uint base, uint power)
{
  uint result = 1;
  uint i;
  for (i = 0; i < power; i++)
    result *= base;
  return result;
}
