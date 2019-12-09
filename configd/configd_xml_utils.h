/*
 * Copyright (c) 2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef XML_UTILS_CONFIGD_H_
#define XML_UTILS_CONFIGD_H_

#include <libnetconf_xml.h>

extern char *configd_get_rpc_value(const char *rpc_name, const char *attr_name, const nc_rpc *rpc);

extern int configd_rpc_value_exists(const char *rpc_name, const char *attr_name, const nc_rpc *rpc);

#endif /* XML_UTILS_CONFIGD_H_ */
