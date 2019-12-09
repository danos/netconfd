/*
 * netconfd
 * Copyright (c) 2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * Copyright (c) 2014-2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * Based on the netopeer server-sl code:
 * netopeer-server-sl (main.c)
 * Author Radek Krejci <rkrejci@cesnet.cz>
 *
 * Example implementation of event-driven NETCONF server using libnetconf.
 *
 * Copyright (C) 2012-2013 CESNET, z.s.p.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is, and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <dirent.h>
#include <regex.h>

#include <event2/event.h>

#include <libnetconf_xml.h>

#include "configd/configd_datastore.h"

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

#define NC_CAP_WRUNNING_ID      "urn:ietf:params:netconf:capability:writable-running:1.0"
#define NC_CAP_CONFIRMED_COMMIT_ID "urn:ietf:params:netconf:capability:confirmed-commit:1.1"
#define NC_CAP_ROLLBACK_ID      "urn:ietf:params:netconf:capability:rollback-on-error:1.0"
#define NC_CAP_VALIDATE11_ID    "urn:ietf:params:netconf:capability:validate:1.1"
#define NC_CAP_VALIDATE10_ID    "urn:ietf:params:netconf:capability:validate:1.0"

static struct configd_ds *configd_ds = NULL;

struct srv_config {
	struct nc_session *session;
	ncds_id dsid;
	struct event_base *event_base;
	struct event *event_input;
};

struct ntf_thread_config {
	struct nc_session *session;
	nc_rpc *subscribe_rpc;
};

void clb_print(NC_VERB_LEVEL level, const char* msg)
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


void process_rpc(evutil_socket_t UNUSED(in), short UNUSED(events), void *arg)
{
	nc_rpc *rpc = NULL;
	nc_reply *reply = NULL;
	NC_RPC_TYPE req_type;
	NC_OP req_op;
	struct nc_err *e;
	int ret;
	struct srv_config *config = (struct srv_config*)arg;

	/* receive incoming message */
	ret = nc_session_recv_rpc(config->session, -1, &rpc);
	if (ret != NC_MSG_RPC) {
		switch(ret) {
		case NC_MSG_NONE:
			/* the request was already processed by libnetconf or no message available */
			return;
		case NC_MSG_UNKNOWN:
			if (nc_session_get_status(config->session) != NC_SESSION_STATUS_WORKING) {
				/* something really bad happend, and communication os not possible anymore */
				event_base_loopbreak(config->event_base);
			}
			return;
		default:
			return;
		}
	}

	/* process it */
	req_type = nc_rpc_get_type(rpc);
	req_op = nc_rpc_get_op(rpc);
	if (req_type == NC_RPC_SESSION) {
		/* process operations affectinf session */
		switch(req_op) {
		case NC_OP_CLOSESESSION:
			/* exit the event loop immediately without processing any following request */
			reply = nc_reply_ok();
			event_base_loopbreak(config->event_base);
			break;
		case NC_OP_KILLSESSION:
			/* todo: kill the requested session */
			reply = nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
			break;
		default:
			reply = nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
			break;
		}
	} else if (req_type == NC_RPC_DATASTORE_READ) {
		/* process operations reading datastore */
		switch (req_op) {
		case NC_OP_GET:
			reply =  configd_ds_get(configd_ds, rpc);
			break;
		case NC_OP_GETSCHEMA:
		case NC_OP_GETCONFIG:
		case NC_OP_VALIDATE:
			reply = configd_ds_apply_rpc(configd_ds, rpc);
			break;
		default:
			reply = nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
			break;
		}
	} else if (req_type == NC_RPC_DATASTORE_WRITE) {
		/* process operations affecting datastore */
		switch (req_op) {
		case NC_OP_LOCK:
		case NC_OP_UNLOCK:
		case NC_OP_COPYCONFIG:
		case NC_OP_DELETECONFIG:
		case NC_OP_EDITCONFIG:
		case NC_OP_COMMIT:
		case NC_OP_DISCARDCHANGES:
		case NC_OP_CANCELCOMMIT:
			reply = configd_ds_apply_rpc(configd_ds, rpc);
			break;
		default:
			reply = nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
			break;
		}
	} else {
		/* process other operations */
		reply = configd_run_op_rpc(configd_ds, rpc);
	}

	/* create reply */
	if (reply == NULL) {
		reply = nc_reply_error(nc_err_new(NC_ERR_OP_FAILED));
	} else if (reply == NCDS_RPC_NOT_APPLICABLE) {
		e = nc_err_new(NC_ERR_OP_FAILED);
		nc_err_set(e, NC_ERR_PARAM_MSG, "Requested operation cannot be performed on the managed datastore.");
		reply = nc_reply_error(e);
	}

	/* and send the reply to the client */
	nc_session_send_reply(config->session, rpc, reply);
	nc_rpc_free(rpc);
	nc_reply_free(reply);

	/* and run again when a next message comes */
}

static void setup_configd_caps(struct nc_cpblts* cap)
{
	char *c;
	char buf[1024];
	int len = 0;

	FILE *f = popen("/usr/bin/configdcaps", "r");

	while ((c = fgets(buf, 1024, f)) != NULL) {
		len = strlen(c);
		if (buf[len - 1] == '\n') {
			buf[len - 1] = '\0';
		}
		nc_cpblts_add(cap, c);
	}

	pclose(f);
}

int main(int UNUSED(argc), char** UNUSED(argv))
{
	struct srv_config config;
	int init;

	/* set verbosity and function to print libnetconf's messages */
	nc_verbosity(NC_VERB_WARNING);

	/* set message printing into the system log */
	openlog("netconfd", LOG_PID | LOG_PERROR, LOG_DAEMON);
	nc_callback_print(clb_print);

	init = nc_init(NC_INIT_MONITORING | NC_INIT_SINGLELAYER | NC_INIT_WD);
	if (init == -1) {
		clb_print(NC_VERB_ERROR, "libnetconf initiation failed.");
		return (EXIT_FAILURE);
	}

	/* prepare configuration datastore */
	/*
	 * We are purposly avoiding libnetconf's datastore abstraction
	 * as configd does or will do the equivilant work
	 */
	configd_ds = new_configd_ds();
	if (configd_ds_init(configd_ds) != EXIT_SUCCESS) {
		clb_print(NC_VERB_ERROR, "Initiating datastore failed.");
		return (EXIT_FAILURE);
	}

	/* setup NETCONF server capabilities */
	ncdflt_set_basic_mode(NCWD_MODE_EXPLICIT);
	ncdflt_set_supported(NCWD_MODE_ALL);
	struct nc_cpblts* cap = nc_session_get_cpblts_default();
	nc_cpblts_remove(cap, NC_CAP_WRUNNING_ID);
	nc_cpblts_add(cap, NC_CAP_CONFIRMED_COMMIT_ID);
	nc_cpblts_add(cap, NC_CAP_VALIDATE11_ID);
	nc_cpblts_add(cap, NC_CAP_VALIDATE10_ID);
	setup_configd_caps(cap);

	/* create the NETCONF session -- accept incoming connection */
	config.session = nc_session_accept(cap);
	if (config.session == NULL) {
		clb_print(NC_VERB_ERROR, "Session not established.\n");
		return (EXIT_FAILURE);
	}

	/* monitor the session */
	nc_session_monitor(config.session);

	/* prepare event base (libevent) */
	config.event_base = event_base_new();
	if (config.event_base == NULL) {
		clb_print(NC_VERB_ERROR, "Event base initialisation failed.\n");
		return (EXIT_FAILURE);
	}

	config.event_input = event_new(config.event_base, (evutil_socket_t)nc_session_get_eventfd(config.session), EV_READ | EV_PERSIST, process_rpc, (void*) (&config));
	/* add the event to the event base and run the main event loop */
	event_add (config.event_input, NULL);
	event_base_dispatch(config.event_base);

	/* cleanup */
	event_free(config.event_input);
	event_base_free(config.event_base);
	nc_cpblts_free(cap);
	nc_session_free(config.session);

	nc_close();

	/* bye, bye */
	return EXIT_SUCCESS;
}
