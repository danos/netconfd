/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
 * Copyright (c) 2015 Brocade Communications Systems
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <libnetconf.h>
#include <libnetconf_ssh.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <vyatta-cfg/client/mgmt.h>
#include <vyatta-util/map.h>


extern char *program_invocation_short_name;

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

static void clb_print(NC_VERB_LEVEL level, const char* msg)
{
	switch (level) {
	case NC_VERB_ERROR:
		fprintf(stderr, "libnetconf ERROR: %s\n", msg);
		break;
	case NC_VERB_WARNING:
		fprintf(stderr, "libnetconf WARNING: %s\n", msg);
		break;
	case NC_VERB_VERBOSE:
		fprintf(stderr, "libnetconf VERBOSE: %s\n", msg);
		break;
	case NC_VERB_DEBUG:
		fprintf(stderr, "libnetconf DEBUG: %s\n", msg);
		break;
	}
}

static void clb_error_print(const char* tag,
		const char* type,
		const char* severity,
		const char* UNUSED(apptag),
		const char* UNUSED(path),
		const char* message,
		const char* UNUSED(attribute),
		const char* UNUSED(element),
		const char* UNUSED(ns),
		const char* UNUSED(sid))
{
	fprintf(stderr, "NETCONF %s: %s (%s) - %s\n", severity, tag, type, message);
}

static void usage(void)
{
	printf("Usage: %s [-h] [-p <port>] [-u <user>]\n", program_invocation_short_name);
	printf("-h             Show this help\n");
	printf("-p <port>      Connect to a specific port, 830 is default port\n");
	printf("-u <user>      Connect as a specific user, current user is used by default\n");
	printf("-v             Verbose mode\n\n");
}

int main(int argc, char* argv[])
{
	int ret = EXIT_SUCCESS;
	NC_VERB_LEVEL verbosity = NC_VERB_WARNING;
	struct nc_session *session;
	unsigned short port = 830;
	char* user = NULL;
	char *data = NULL;
	nc_rpc *rpc = NULL;
	nc_reply *reply = NULL;
	NC_REPLY_TYPE reply_type;
	int c, timeout = -1;

	while ((c = getopt(argc, argv, "hu:p:v")) != -1) {
		switch (c) {
		case 'h': /* Show help */
			usage();
			return EXIT_SUCCESS;
		case 'p': /* port */
			port = atoi (optarg);
			break;
		case 'u': /* user */
			user = optarg;
			break;
		case 'v': /* Verbosity operation */
			if (++verbosity > NC_VERB_DEBUG)
				verbosity = NC_VERB_DEBUG;
			break;
		default:
			fprintf(stderr, "unknown argument -%c", optopt);
			break;
		}
	}

	/* set verbosity and function to print libnetconf's messages */
	nc_verbosity(verbosity);
	nc_callback_print(clb_print);
	nc_callback_error_reply(clb_error_print);

	/* create NETCONF session */
	fprintf(stdout, "Listening on port %d for user %s.\n",
			port, user ? user : "current user");
	if (nc_callhome_listen(port)) {
		fputs("Unable to establish listen port\n", stderr);
		exit(EXIT_FAILURE);
	}
	struct nc_cpblts *cpblts = nc_session_get_cpblts_default();
	session = nc_callhome_accept(user, cpblts, &timeout);
	if (session == NULL) {
		fprintf(stderr, "Connecting to the NETCONF server failed.\n");
		return (EXIT_FAILURE);
	}
	nc_cpblts_free(cpblts);

	/*
	 * Get configuration as well as status data
	 */

	/* first prepare <get> message */
	rpc = nc_rpc_get(NULL);
	if (rpc == NULL ) {
		fprintf(stderr, "Creating <get> RPC message failed.\n");
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/* send <rpc> and receive <rpc-reply> */
	switch (nc_session_send_recv(session, rpc, &reply)) {
	case NC_MSG_UNKNOWN:
		fprintf(stderr, "Sending/Receiving NETCONF message failed.\n");
		ret = EXIT_FAILURE;
		goto cleanup;

	case NC_MSG_NONE:
		/* error occurred, but processed by callback */
		goto cleanup;

	case NC_MSG_REPLY:
		if ((reply_type = nc_reply_get_type(reply)) == NC_REPLY_DATA) {
			fprintf(stdout, "%s\n", data = nc_reply_get_data(reply));
			free(data);
		} else {
			fprintf(stderr, "Unexpected type of message received (%d).\n", reply_type);
			ret = EXIT_FAILURE;
			goto cleanup;
		}
		break;

	default:
		fprintf(stderr, "Unknown error occurred.\n");
		ret = EXIT_FAILURE;
		goto cleanup;
	}

cleanup:
	/* free messages */
	nc_rpc_free(rpc);
	nc_reply_free(reply);

	/* close NETCONF session */
	nc_session_free(session);
	exit(ret);
}

