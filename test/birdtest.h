/*
 *	BIRD -- Unit Test Framework (BIRD Test)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRDTEST_H_
#define _BIRDTEST_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#include "nest/bird.h"

extern int bt_result;
extern int bt_suite_result;

extern uint bt_verbose;
#define BT_VERBOSE_NO			0
#define BT_VERBOSE_SUITE		1
#define BT_VERBOSE_SUITE_CASE		2
#define BT_VERBOSE_ABSOLUTELY_ALL	3

extern const char *bt_filename;
extern const char *bt_test_id;

void bt_init(int argc, char *argv[]);
int  bt_exit_value(void);
void bt_test_suite_base(int (*test_fn)(const void *), const char *test_id, const void *test_fn_argument, int forked, int timeout, const char *dsc, ...);
long int bt_random(void);

void bt_log_suite_result(int result, const char *fmt, ...);
void bt_log_suite_case_result(int result, const char *fmt, ...);

#define BT_SUCCESS 			1
#define BT_FAILURE 			0

#define BT_TIMEOUT 			5	/* Default timeout in seconds */
#define BT_FORKING 			1	/* Forking is enabled in default */

#define BT_RANDOM_SEED 			982451653

#define BT_BUFFER_SIZE 			10000

#define BT_PROMPT_GREEN 		"\e[1;32m"
#define BT_PROMPT_RED 			"\e[1;31m"
#define BT_PROMPT_NORMAL		"\e[0m"
#define BT_PROMPT_OK			" [" BT_PROMPT_GREEN " OK " BT_PROMPT_NORMAL "] "
#define BT_PROMPT_OK_NO_COLOR		" ["                 " OK "                  "] "
#define BT_PROMPT_FAIL			" [" BT_PROMPT_RED   "FAIL" BT_PROMPT_NORMAL "] "
#define BT_PROMPT_FAIL_NO_COLOR		" ["                 "FAIL"                  "] "
#define BT_PROMPT_OK_FAIL_STRLEN	8	/* strlen ' [FAIL] ' */

#define bt_test_suite(fn, dsc, ...) \
  bt_test_suite_extra(fn, BT_FORKING, BT_TIMEOUT, dsc, ##__VA_ARGS__)

#define bt_test_suite_extra(fn, f, t, dsc, ...) \
  bt_test_suite_base((int (*)(const void *))fn, #fn, NULL, f, t, dsc, ##__VA_ARGS__)

#define bt_test_suite_arg(fn, arg, dsc, ...) \
  bt_test_suite_arg_extra(fn, arg, BT_FORKING, BT_TIMEOUT, dsc, ##__VA_ARGS__)

#define bt_test_suite_arg_extra(fn, arg, f, t, dsc, ...) \
  bt_test_suite_base(fn, #fn, arg, f, t, dsc, ##__VA_ARGS__)

#define bt_abort() \
  bt_abort_msg("Aborted at %s:%d", __FILE__, __LINE__)

#define bt_abort_msg(format, ...) 					\
  do 									\
  { 									\
    bt_log(format, ##__VA_ARGS__); 					\
    abort(); 								\
  } while (0)

#define bt_log(format, ...) 						\
  do 									\
  {	 								\
    if (bt_test_id) 							\
      printf("%s: %s: " format "\n", bt_filename, bt_test_id, ##__VA_ARGS__); \
    else 								\
      printf("%s: " format "\n", bt_filename, ##__VA_ARGS__);		\
  } while(0)

#define bt_debug(format, ...) 						\
  do 									\
  { 									\
    if (bt_verbose >= BT_VERBOSE_ABSOLUTELY_ALL)			\
      printf(format, ##__VA_ARGS__); 					\
  } while (0)

#define bt_assert(test) \
  bt_assert_msg(test, "Assertion (%s) at %s:%d", #test, __FILE__, __LINE__)

#define bt_assert_msg(test, format, ...)				\
  do 									\
  {									\
    int bt_suit_case_result = BT_SUCCESS;				\
    if ((test) == 0) 							\
    {									\
      bt_suite_result = BT_FAILURE;					\
      bt_suit_case_result = BT_FAILURE;					\
    }									\
    bt_log_suite_case_result(bt_suit_case_result, format, ##__VA_ARGS__); \
  } while (0)

#define bt_syscall(test, format, ...) 					\
  do 									\
  { 									\
    if (test) 								\
    {									\
      bt_log(format ": %s", ##__VA_ARGS__, strerror(errno)); 		\
      exit(3);								\
    }									\
  } while (0)

/* Internal, please don't use it directly */
#define bt_sprintf_concat(s, format, ...) \
  snprintf(s + strlen(s), sizeof(s) - strlen(s), format, ##__VA_ARGS__)

/* Internal, please don't use it directly */
#define bt_dump_struct(buf3, data)					\
  do									\
  {									\
    uint k;								\
    u32 *pc = (u32*) data;						\
    bt_sprintf_concat(buf3, "{");					\
    for (k = 0; k < (sizeof(*data) / sizeof(typeof(*pc))); k++)		\
    {									\
      bt_sprintf_concat(buf3, "%s0x%08X", (k ? ", " : ""), pc[k]);	\
    }									\
    bt_sprintf_concat(buf3, "}");					\
  } while (0)

/* Internal, please don't use it directly */
#define bt_dump(buf2, data, fmt)					\
  do									\
  {									\
    if (fmt == NULL)							\
    {									\
      bt_dump_struct(buf2, &data);					\
    }									\
    else								\
    {									\
      bt_sprintf_concat(buf2, fmt, data);				\
    }									\
  } while (0)

/* Internal, please don't use it directly */
#define bt_log_suite_case_result__(fn, in, out, fn_out, in_fmt, out_fmt, result) \
  do									\
  {									\
    char buf1[BT_BUFFER_SIZE];						\
    snprintf(buf1, sizeof(buf1), "%s(", #fn);				\
    bt_dump(buf1, in, in_fmt);						\
    bt_sprintf_concat(buf1, ") gives ");				\
    bt_dump(buf1, fn_out, out_fmt);					\
    if (result != BT_SUCCESS) 						\
    {									\
      bt_sprintf_concat(buf1, ", but expecting is ");			\
      bt_dump(buf1, out, out_fmt);					\
    } 									\
    bt_log_suite_case_result(result, "%s: %s", bt_test_id, buf1);	\
  } while (0)

/**
 * Usage:
 * 	u32 my_function(const char *input_data) { ... }
 *
 *	struct in_out {
 *     		char *in;
 *   		u32  out;
 * 	} in_out[] = { ... };
 *
 * 	bt_assert_out_fn_in(my_function, in_out, "%s", "%u");
 */
#define bt_assert_out_fn_in(fn, in_out, in_fmt, out_fmt)		\
  do									\
  {									\
    uint i;								\
    for (i = 0; i < (sizeof(in_out)/sizeof(in_out[0])); i++)		\
    {									\
      int bt_suit_case_result = BT_SUCCESS;				\
      typeof(in_out[i].out) fn_out = fn(in_out[i].in);			\
      if (fn_out != in_out[i].out)					\
      { 								\
	bt_suite_result = BT_FAILURE;					\
	bt_suit_case_result = BT_FAILURE;				\
      }									\
      bt_log_suite_case_result__(fn, in_out[i].in, in_out[i].out, fn_out, in_fmt, out_fmt, bt_suit_case_result); \
    }									\
  } while (0)

/**
 * Usage:
 * 	void my_function(const char *input_data, u32 *output_data) { ... }
 *
 *	struct in_out {
 *     		char *in;
 *   		u32  out;
 * 	} in_out[] = { ... };
 *
 * 	bt_assert_fn_in_out(my_function, in_out, "%s", "%u");
 */
#define bt_assert_fn_in_out(fn, in_out, in_fmt, out_fmt)		\
  do									\
  {									\
    uint i;								\
    for (i = 0; i < (sizeof(in_out)/sizeof(in_out[0])); i++)		\
    {									\
      int bt_suit_case_result = BT_SUCCESS;				\
      typeof(in_out[i].out) fn_out;					\
      bzero(&fn_out, sizeof(fn_out));					\
      fn(in_out[i].in, &fn_out);					\
      if (memcmp(&fn_out, &in_out[i].out, sizeof(in_out[i].out)))	\
      {									\
	bt_suite_result = BT_FAILURE;					\
	bt_suit_case_result = BT_FAILURE;				\
      }									\
      bt_log_suite_case_result__(fn, in_out[i].in, in_out[i].out, fn_out, in_fmt, out_fmt, bt_suit_case_result); \
    }									\
  } while (0)

#endif /* _BIRDTEST_H_ */
