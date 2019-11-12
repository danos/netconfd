/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Unit test mocks (stubs) for vyatta-cfg functions
 */

#include "CppUTest/TestHarness_c.h"
#include "CppUTestExt/MockSupport_c.h"
#include <string.h>

#include "stubs.h"

#include <vyatta-cfg/client/mgmt.h>

char *configd_call_rpc_xml(struct configd_conn *conn,
			   const char *ns, const char *name,
			   const char *input, struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(NULL);
}

void configd_close_connection(struct configd_conn *conn)
{
	CPPUTEST_STUB_RET;
}

char *configd_commit(
	struct configd_conn *conn,
	const char * param,
	struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(NULL);
}

char *configd_discard(
	struct configd_conn *conn,
	struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(NULL);
}

char *configd_edit_config_xml(
	struct configd_conn *conn,
	const char *config_target,
	const char *default_operation,
	const char *test_option,
	const char *error_option,
	const char *config,
	struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(NULL);
}

void configd_error_free(struct configd_error *error)
{
	mock_c()->actualCall("configd_error_free");
}

char *configd_get_schemas(
	struct configd_conn *conn,
	struct configd_error *error)
{
	// Cast prevents 'ignoring const' compiler warning.
	return (char *)mock_c()->actualCall("configd_get_schemas")
		->returnValue().value.stringValue;
}

int configd_load(
	struct configd_conn *conn,
	const char *param,
	struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(0);
}

int configd_open_connection(struct configd_conn *conn)
{
	CPPUTEST_STUB_RET_VAL(0);
}

char *configd_save(
	struct configd_conn *conn,
	const char *param,
	struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(NULL);
}

char *configd_schema_get(
	struct configd_conn *conn,
	const char *module,
	const char *fmt,
	struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(NULL);
}

int configd_sess_exists(
	struct configd_conn *conn,
	struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(0);
}

int configd_sess_setup(
	struct configd_conn *conn,
	struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(0);
}

int configd_sess_lock(struct configd_conn *conn, struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(0);
}

int configd_sess_unlock(struct configd_conn *conn, struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(0);
}

int configd_sess_locked(struct configd_conn *conn, struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(0);
}

int configd_sess_changed(struct configd_conn *conn, struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(0);
}

int configd_set_session_id(struct configd_conn *conn, const char *param)
{
	CPPUTEST_STUB_RET_VAL(0);
}

struct map *configd_tmpl_get(
	struct configd_conn *conn,
	const char *cpath,
	struct configd_error *error)
{
	return (struct map *)mock_c()->actualCall("configd_tmpl_get")
		->withStringParameters("cpath", cpath)
		->returnValue().value.stringValue;
}

char *configd_tree_get_encoding_flags(
	struct configd_conn *conn,
	int db,
	const char *path,
	const char *encoding,
	unsigned int flags,
	struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(NULL);
}

char *configd_tree_get_full_encoding_flags(
	struct configd_conn *conn,
	int db,
	const char *path,
	const char *encoding,
	unsigned int flags,
	struct configd_error *error)
{
	// Cast prevents 'ignoring const' compiler warning.
	return (char *)mock_c()->actualCall("configd_tree_get_full_encoding_flags")
		->withStringParameters("path", path)
		->returnValue().value.stringValue;
}

char *configd_validate(struct configd_conn *conn, struct configd_error *error)
{
	CPPUTEST_STUB_RET_VAL(NULL);
}
