/*
 *	BIRD Internet Routing Daemon -- MPLS label switching protocol
 *
 *	(c) 2016 Jan Moskyto Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_LIB_MPLS_H_
#define _BIRD_LIB_MPLS_H_

#define MPLS_LABEL_UNKNOWN ~(0U)

/* Reserved labels from http://www.iana.org/assignments/mpls-label-values/mpls-label-values.xhtml */
enum mpls_reserved_labels {
  /* RFC 3032 reserved NULL labels */
  MPLS_LABEL_NULL_IP4 = 0,
  MPLS_LABEL_ROUTER_ALERT,
  MPLS_LABEL_NULL_IP6,
  MPLS_LABEL_NULL_IMPLICIT,
  /* 4-6 reserved for future use */
  MPLS_LABEL_ELI = 7, /* RFC 6790 */
  /* 8-12 reserved for future use */
  MPLS_LABEL_GAL = 13, /* RFC 5586 */
  MPLS_LABEL_OAM = 14, /* RFC 3429 */
  MPLS_LABEL_XL = 15, /* RFC 7274 */
};

#define MPLS_MAX_LABEL_STACK 8
static inline int
mpls_get(const char *buf, int buflen, u32 *stack)
{
  for (int i=0; (i<MPLS_MAX_LABEL_STACK) && (i*4+3 < buflen); i++)
  {
    u32 s = get_u32(buf + i*4);
    stack[i] = s >> 12;
    if (s & 0x100)
      return i+1;
  }
  return -1;
}

static inline int
mpls_put(char *buf, int len, u32 *stack)
{
  for (int i=0; i<len; i++)
    put_u32(buf + i*4, stack[i] << 12 | (i+1 == len ? 0x100 : 0));

  return len*4;
}

#endif
