/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef PATH_CONFIGD_H_
#define PATH_CONFIGD_H_

#include <libnetconf_xml.h>
#include <vyatta-cfg/client/mgmt.h>

// Used to tell configd to return ALL data.
#define ROOT_PATH ""

// Used when RPC / filter is invalid and there is no point querying for data.
#define NO_PATH "NO_PATH"

struct configd_ds {
	struct configd_conn conn;
	int lockid;
};

extern xmlNode *get_first_element(xmlNode *node);

extern char *configd_strdup(char *src);

extern char *configd_convert_filter_to_config_path(
	const nc_rpc *rpc, struct configd_ds *ds);

#endif /* PATH_CONFIGD_H_ */
