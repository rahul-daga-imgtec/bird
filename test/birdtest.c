/*
 *	BIRD -- Unit Test Framework (BIRD Test)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "test/birdtest.h"
#include "sysdep/autoconf.h"

#ifdef HAVE_EXECINFO_H
#include <execinfo.h>
#endif

#define BACKTRACE_MAX_LINES 100

static const char *request;
static int list_tests;
static int do_core;
static int no_fork;
static int no_timeout;
static int is_terminal;		/* Whether stdout is a live terminal or pipe redirect */

uint bt_verbose;
const char *bt_filename;
const char *bt_test_id;

int bt_result;			/* Overall program run result */
int bt_suite_result;		/* One suit result */

long int
bt_random(void)
{
  /* Seeded in bt_init() */
  long int rand_low, rand_high;

  rand_low = random();
  rand_high = random();
  return (rand_low & 0xffff) | ((rand_high & 0xffff) << 16);
}

void
bt_init(int argc, char *argv[])
{
  int c;

  srandom(BT_RANDOM_SEED);

  bt_verbose = 0;
  bt_filename = argv[0];
  bt_result = BT_SUCCESS;
  bt_test_id = NULL;
  is_terminal = isatty(fileno(stdout));

  while ((c = getopt(argc, argv, "lcftv")) >= 0)
    switch (c)
    {
      case 'l':
	list_tests = 1;
	return;

      case 'c':
	do_core = 1;
	break;

      case 'f':
	no_fork = 1;
	break;

      case 't':
	no_timeout = 1;
	break;

      case 'v':
	bt_verbose++;
	break;

      default:
	goto usage;
    }

  /* Optional requested test_id */
  if ((optind + 1) == argc)
    request = argv[optind++];

  if (optind != argc)
    goto usage;

  if (do_core)
  {
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    int rv = setrlimit(RLIMIT_CORE, &rl);
    bt_syscall(rv < 0, "setrlimit RLIMIT_CORE");
  }

  return;

 usage:
  printf("Usage: %s [-l] [-c] [-f] [-t] [-vvv] [<test_suit_name>]\n", argv[0]);
  printf("Options: \n");
  printf("  -l   List all test suite names and descriptions \n");
  printf("  -c   Force unlimit core dumps (needs root privileges) \n");
  printf("  -f   No forking \n");
  printf("  -t   No timeout limit \n");
  printf("  -v   More verbosity, maximum is 3 -vvv \n");
  exit(3);
}

static void
bt_dump_backtrace(void)
{
#ifdef HAVE_EXECINFO_H
  void *buf[BACKTRACE_MAX_LINES];
  char **pp_backtrace;
  int lines, j;

  if (!bt_verbose)
    return;

  lines = backtrace(buf, BACKTRACE_MAX_LINES);
  bt_log("backtrace() returned %d addresses", lines);

  pp_backtrace = backtrace_symbols(buf, lines);
  if (pp_backtrace == NULL)
  {
    perror("backtrace_symbols");
    exit(EXIT_FAILURE);
  }

  for (j = 0; j < lines; j++)
    bt_log("%s", pp_backtrace[j]);

  free(pp_backtrace);
#endif /* HAVE_EXECINFO_H */
}

static
int bt_run_test_fn(int (*fn)(const void *), const void *fn_arg, int timeout)
{
  int result;
  alarm(timeout);

  if (fn_arg)
    result = fn(fn_arg);
  else
    result = ((int (*)(void))fn)();

  if (bt_suite_result != BT_SUCCESS)
    result = BT_FAILURE;

  return result;
}

static uint
get_num_terminal_cols(void)
{
  struct winsize w = {};
  ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
  uint cols = w.ws_col;
  return (cols > 0 ? cols : 80);
}

/**
 * bt_log_result - pretty print of test result
 * @result: BT_SUCCESS or BT_FAILURE
 * @fmt: a description message (could be long, over more lines)
 * @argptr: variable argument list
 *
 * This function is used for pretty printing of test results on all verbose
 * levels.
 */
static void
bt_log_result(int result, const char *fmt, va_list argptr)
{
  char fmt_buf[BT_BUFFER_SIZE];
  char msg_buf[BT_BUFFER_SIZE];
  char *pos;

  snprintf(msg_buf, sizeof(msg_buf), "%s%s %s%s",
	   bt_filename,
	   bt_test_id ? ": " : "",
	   bt_test_id ? bt_test_id : "",
	   (bt_test_id && fmt) ? ": " : "");
  pos = msg_buf + strlen(msg_buf);

  vsnprintf(pos, sizeof(msg_buf) - (pos - msg_buf), fmt, argptr);

  /* 'll' means here Last Line */
  uint cols = get_num_terminal_cols();
  uint ll_len = (strlen(msg_buf) % cols) + BT_PROMPT_OK_FAIL_STRLEN;
  uint ll_offset = (ll_len / get_num_terminal_cols() + 1) * cols - BT_PROMPT_OK_FAIL_STRLEN;
  uint offset = ll_offset + (strlen(msg_buf) / cols) * cols;
  snprintf(fmt_buf, sizeof(fmt_buf), "%%-%us%%s\n", offset);

  const char *result_str = is_terminal ? BT_PROMPT_OK : BT_PROMPT_OK_NO_COLOR;
  if (result != BT_SUCCESS)
    result_str = is_terminal ? BT_PROMPT_FAIL : BT_PROMPT_FAIL_NO_COLOR;

  printf(fmt_buf, msg_buf, result_str);
}

/**
 * bt_log_overall_result - pretty print of suite case result
 * @result: BT_SUCCESS or BT_FAILURE
 * @fmt: a description message (could be long, over more lines)
 * ...: variable argument list
 *
 * This function is used for pretty printing of test suite case result.
 */
static void
bt_log_overall_result(int result, const char *fmt, ...)
{
  va_list argptr;
  va_start(argptr, fmt);
  bt_log_result(result, fmt, argptr);
  va_end(argptr);
}

/**
 * bt_log_suite_result - pretty print of suite case result
 * @result: BT_SUCCESS or BT_FAILURE
 * @fmt: a description message (could be long, over more lines)
 * ...: variable argument list
 *
 * This function is used for pretty printing of test suite case result.
 */
void
bt_log_suite_result(int result, const char *fmt, ...)
{
  if(bt_verbose >= BT_VERBOSE_SUITE)
  {
    va_list argptr;
    va_start(argptr, fmt);
    bt_log_result(result, fmt, argptr);
    va_end(argptr);
  }
}

/**
 * bt_log_suite_case_result - pretty print of suite result
 * @result: BT_SUCCESS or BT_FAILURE
 * @fmt: a description message (could be long, over more lines)
 * ...: variable argument list
 *
 * This function is used for pretty printing of test suite result.
 */
void
bt_log_suite_case_result(int result, const char *fmt, ...)
{
  if(bt_verbose >= BT_VERBOSE_SUITE_CASE)
  {
    va_list argptr;
    va_start(argptr, fmt);
    bt_log_result(result, fmt, argptr);
    va_end(argptr);
  }
}

void
bt_test_suite_base(int (*fn)(const void *), const char *id, const void *fn_arg, int forked, int timeout, const char *dsc, ...)
{
  if (list_tests)
  {
    printf("%28s - ", id);
    va_list args;
    va_start(args, dsc);
    vprintf(dsc, args);
    va_end(args);
    printf("\n");
    return;
  }

  if (no_fork)
    forked = 0;

  if (no_timeout)
    timeout = 0;

  if (request && strcmp(id, request))
    return;

  bt_suite_result = BT_SUCCESS;
  bt_test_id = id;

  if (bt_verbose >= BT_VERBOSE_ABSOLUTELY_ALL)
    bt_log("Starting");

  if (!forked)
  {
    bt_run_test_fn(fn, fn_arg, timeout);
  }
  else
  {
    pid_t pid = fork();
    bt_syscall(pid < 0, "fork");

    if (pid == 0)
    {
      /* child of fork */
      _exit(bt_run_test_fn(fn, fn_arg, timeout));
    }

    int s;
    int rv = waitpid(pid, &s, 0);
    bt_syscall(rv < 0, "waitpid");

    bt_suite_result = 2;
    if (WIFEXITED(s))
    {
      /* Normal exit */
      bt_suite_result = WEXITSTATUS(s);
    }
    else if (WIFSIGNALED(s))
    {
      /* Stopped by signal */
      bt_suite_result = BT_FAILURE;

      int sn = WTERMSIG(s);
      if (sn == SIGALRM)
      {
	bt_log("Timeout expired");
      }
      else if (sn == SIGSEGV)
      {
	bt_log("Segmentation fault");
	bt_dump_backtrace();
      }
      else if (sn != SIGABRT)
	bt_log("Signal %d received", sn);
    }

    if (WCOREDUMP(s))
      bt_log("Core dumped");
  }

  if (bt_suite_result == BT_FAILURE)
    bt_result = BT_FAILURE;

  bt_log_suite_result(bt_suite_result, NULL);
  bt_test_id = NULL;
}

int
bt_exit_value(void)
{
  if (list_tests)
    return EXIT_SUCCESS;

  bt_log_overall_result(bt_result, "");
  return bt_result == BT_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}

/*
 * Mock-ups of all necessary public functions in main.c
 */

char *bird_name;
void async_config(void) {}
void async_dump(void) {}
void async_shutdown(void) {}
void cmd_check_config(char *name) {}
void cmd_reconfig(char *name, int type, int timeout) {}
void cmd_reconfig_confirm(void) {}
void cmd_reconfig_undo(void) {}
void cmd_shutdown(void) {}
void cmd_reconfig_undo_notify(void) {}

#include "nest/bird.h"
#include "lib/net.h"
#include "conf/conf.h"
void sysdep_preconfig(struct config *c) {}
int sysdep_commit(struct config *new, struct config *old UNUSED) { return 0; }
void sysdep_shutdown_done(void) {}

#include "nest/cli.h"
int cli_get_command(cli *c) { return 0; }
void cli_write_trigger(cli *c) {}
cli *cmd_reconfig_stored_cli;
