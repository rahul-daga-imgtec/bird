/*
 *	BIRD Library -- Flow specification (RFC 5575)
 *
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"

uint
fsc_get_length(const void *nlri)
{
  const u8 *byte  = nlri;

  if ((*byte & 0xf0) == 0xf0)
    return ((*byte & 0xf) << 8) + *(byte+1);

  return *byte;
}
