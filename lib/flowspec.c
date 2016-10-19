/*
 *	BIRD Library -- Flow specification (RFC 5575)
 *
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/flowspec.h"

uint
flow_get_length(const byte *b)
{
  return ((*b & 0xf0) == 0xf0) ? get_u16(b) & 0x0fff : *b;
}
