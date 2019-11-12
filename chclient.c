/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
 * Copyright (c) 2015 Brocade Communications Systems
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include <libnetconf.h>
#include <libnetconf_ssh.h>

extern char *program_invocation_short_name;

static const char *status_file = "/run/chclient";

typedef enum {
	CH_FIRST = -1,
	CH_FAILED = CH_FIRST,
	CH_SUCCESS,
	CH_STARTED,
	CH_NOTSTARTED,
	CH_UNKNOWN,
	CH_LAST = CH_UNKNOWN
} chstatus;

#define CHC_DELAY (5) // seconds
#define CHC_RETRIES (3)

/* All calls must be signal safe */
static void cleanup(void)
{
	unlink(status_file);
}

static void sahandler(int signum) {
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		cleanup();
		_exit(EXIT_SUCCESS);
		break;
	}
}

static const char *get_status_str(chstatus status) {
	// order of strings must be same as chstatus type
	static char *status_str[] = {
		"failed",
		"succeeded",
		"started",
		"not-started",
		"unknown",
		NULL
	};
	if ((status < CH_FIRST) || (status > CH_LAST))
		return NULL;
	return status_str[status + 1];
}

static void print_status_json(void)
{
	char buf[80];
	const char *status = buf;
	FILE *fp = fopen(status_file, "r");
	if (!fp) {
		// lack of a file indicates that call-home was not
		// started
		status = get_status_str(CH_NOTSTARTED);
		goto done;
	}
	if (fgets(buf, sizeof(buf), fp) == NULL) {
		status = get_status_str(CH_UNKNOWN);
	}
	fclose(fp);
done:
	printf("{\"call-home-status\": \"%s\"}", status);
}

static int write_status(const char *status)
{
	int fd;
	int result = -1;

	fd = open(status_file, O_WRONLY | O_CREAT | O_CLOEXEC,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (fd == -1) {
		syslog(LOG_ERR, "Unable to open status file: %s", strerror(errno));
		return -1;
	}
	syslog(LOG_ERR, "Writing status: %s", status);
	if (write(fd, status, strlen(status)) == -1) {
		syslog(LOG_ERR, "Unable to write status file: %s", strerror(errno));
		goto error;
	}
	if (ftruncate(fd, strlen(status)) == -1) {
		syslog(LOG_ERR, "Unable to write status file: %s", strerror(errno));
		goto error;
	}
	result = 0;
error:
	close(fd);
	return result;
}

static int set_status(chstatus chstatus)
{
	const char *stat = get_status_str(chstatus);
	if (!stat) {
		syslog(LOG_ERR, "Invalid status %d", chstatus);
		return -1;
	}

	if (chstatus == CH_STARTED) {
		unlink(status_file);
	}
	write_status(stat);
	return 0;
}

static void clb_print(NC_VERB_LEVEL level, const char* msg)
{

	switch (level) {
	case NC_VERB_ERROR:
		syslog(LOG_ERR, "E| %s", msg);
		break;
	case NC_VERB_WARNING:
		syslog(LOG_WARNING, "W| %s", msg);
		break;
	case NC_VERB_VERBOSE:
		syslog(LOG_INFO, "V| %s", msg);
		break;
	case NC_VERB_DEBUG:
		syslog(LOG_DEBUG, "D| %s", msg);
		break;
	}
}

// serveropt format is:
// - server:port
// - [server]:port for literal IPv6 address
static int add_server(struct nc_mngmt_server **servers, const char *serveropt)
{
	char *server;
	char *sep;
	int result = -1;

	if (!serveropt) {
		errno = EINVAL;
		return -1;
	}

	server = strdup(serveropt);
	if (!server)
		return -1;
	sep = strrchr(server, ':');
	if (!sep || sep == server)
		goto done;

	const char *port = sep + 1;
	const char *host = server;
	*sep-- = '\0';
	if (*sep == ']') {
		*sep = '\0';
		++host;
	}
	struct nc_mngmt_server *new_servers = nc_callhome_mngmt_server_add(*servers, host, port);
	if (new_servers) {
		result = 0;
		*servers = new_servers;
	}
done:
	free(server);
	return result;
}

static int callhome_connect(struct nc_mngmt_server *servers)
{
	int pid, status;
	int result = EXIT_FAILURE;

	set_status(CH_STARTED);
	nc_session_transport(NC_TRANSPORT_SSH);
	pid = nc_callhome_connect(servers, CHC_DELAY, CHC_RETRIES, NULL, NULL, NULL);

	do {
		int c = waitpid(pid, &status, 0);
		if (c == -1) {
			syslog(LOG_ERR, "Unable to wait for callhome child: %s",
			       strerror(errno));
			set_status(CH_FAILED);
			return EXIT_FAILURE;
		}

		if (WIFEXITED(status)) {
			result = WEXITSTATUS(status);
		} else if (WIFSIGNALED(status)) {
			syslog(LOG_WARNING, "W: callhome terminated with signal %d",
			       WTERMSIG(status));
		}
	} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	set_status(result ? CH_FAILED : CH_SUCCESS);
	return result;
}

static void usage(int exitcode)
{
	fprintf(stderr, "Usage: %s [options]...\n\n", program_invocation_short_name);
	fprintf(stderr, "-h|--help               Show this help\n");
	fprintf(stderr, "-g|--get-status         Print call-home status and exit\n");
	fprintf(stderr, "-s|--server <host:port> Specify call-home server and port (can use multiple times)\n");
	fprintf(stderr, "-v|--verbose            Increase verbosity\n\n");
	if (exitcode >= 0)
		exit(exitcode);
}

int main(int argc, char *argv[])
{
	extern int optind, opterr, optopt;
	int opt, opt_ind;
	int verbosity = NC_VERB_WARNING;
	int callhome_servers = 0;
	int result = EXIT_FAILURE;
	struct nc_mngmt_server *servers = NULL;

	static struct option long_options[] = {
		{ "cleanup", 0, NULL, 'c' },
		{ "get-status", 0, NULL, 'g' },
		{ "help", 0, NULL, 'h' },
		{ "server", 1, NULL, 's'},
		{ "verbose", 0, NULL, 'v'},
		{ 0, 0, NULL, 0 }
	};

	static struct sigaction sa = {
		.sa_handler = sahandler,
		.sa_flags = SA_RESTART,
	};

	openlog(program_invocation_short_name, LOG_PID | LOG_PERROR, LOG_DAEMON);

	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		fputs("Unable to install SIGINT handler\n", stderr);
		exit(EXIT_FAILURE);
	}
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		fputs("Unable to install SIGTERM handler\n", stderr);
		exit(EXIT_FAILURE);
	}

	while ((opt = getopt_long(argc, argv, ":cghs:v", long_options, &opt_ind)) != -1) {
		switch (opt) {
		case 'c':
			cleanup();
			exit(EXIT_SUCCESS);
			break;
		case 'g':
			print_status_json();
			exit(EXIT_SUCCESS);
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		case 's':
			if (add_server(&servers, optarg))
				fprintf(stderr, "Unable to add server %s\n", optarg);
			else
				++callhome_servers;
			break;
		case 'v':
			if (++verbosity > NC_VERB_DEBUG)
				verbosity = NC_VERB_DEBUG;
			break;
		case ':':
			fprintf(stderr, "Option %c is missing a parameter; ignoring\n", optopt);
			break;

		case '?':
		default:
			fprintf(stderr, "Unknown option %c; ignoring\n", optopt);
			break;
		}
	}

	nc_verbosity(verbosity);
	nc_callback_print(clb_print);
	if (callhome_servers) {
		result = callhome_connect(servers);
	}
	nc_callhome_mngmt_server_free(servers);
	exit(result);
}
