/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
 * Copyright (c) 2014-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef DATASTORE_CONFIGD_H_
#define DATASTORE_CONFIGD_H_

#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <vyatta-cfg/client/connect.h>

struct configd_ds;

struct configd_ds *new_configd_ds();

int configd_ds_init(void *ds);

void configd_ds_free(void *ds);

nc_reply* configd_ds_get(struct configd_ds *ds, const nc_rpc* rpc);

nc_reply* configd_ds_apply_rpc(struct configd_ds *ds, const nc_rpc* rpc);

nc_reply *configd_run_op_rpc(struct configd_ds *ds, const nc_rpc* rpc);

#endif /* DATASTORE_CONFIGD_H_ */
