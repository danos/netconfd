/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
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
#include <vyatta-cfg/client/mgmt.h>

struct configd_ds;

struct configd_ds *new_configd_ds();

int configd_ds_init(void *ds);

void configd_ds_free(void *ds);

nc_reply *configd_ds_get(struct configd_ds *ds, const nc_rpc *rpc);

nc_reply *configd_ds_apply_rpc(struct configd_ds *ds, const nc_rpc *rpc);

nc_reply *configd_run_op_rpc(struct configd_ds *ds, const nc_rpc *rpc);

// Following functions only really needed for test access.
struct nc_err *nc_err_from_cfg_mgmt_err(struct configd_mgmt_error *me);

nc_reply *configd_ds_basic_nc_error(
    NC_ERR err_type,
    const char *err_text,
    const char *fallback_text);

nc_reply *configd_ds_build_reply_error(
    struct configd_error *ce,
    NC_ERR err_type,
    const char *fallback_text);

#endif /* DATASTORE_CONFIGD_H_ */
