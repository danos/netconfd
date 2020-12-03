/*
 * Copyright (c) 2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <string.h>

#include "configd_datastore.h"
#include "configd_path.h"

#include "CppUTest/TestHarness_c.h"
#include "CppUTestExt/MockSupport_c.h"

#include "netconf_test.h"

#include "error_no_memcheck_cpputest.h"

// mock_nc_err_from_mgmt_err_call
//
// Mock up suitable replies from vyatta-cfg APIs to populate a nc_err from
// a configd_error that contains mgmt_error info.  As it stands, we can only
// verify the message field here as libnetconf does not provide APIs for the
// other fields.  We test those via acceptance tests.
static void mock_nc_err_from_mgmt_err_call(const struct map *info_map) {
	mock_c()->expectOneCall("configd_error_is_mgmt_error")
		->andReturnIntValue(1);
	mock_c()->expectOneCall("configd_mgmt_error_type")
		->andReturnStringValue("TYPE_VALUE");
	mock_c()->expectOneCall("configd_mgmt_error_severity")
		->andReturnStringValue("SEVERITY_VALUE");
	mock_c()->expectOneCall("configd_mgmt_error_tag")
		->andReturnStringValue("TAG_VALUE");
	mock_c()->expectOneCall("configd_mgmt_error_message")
		->andReturnStringValue("MESSAGE_VALUE");
	mock_c()->expectOneCall("configd_mgmt_error_path")
		->andReturnStringValue("PATH_VALUE");
	mock_c()->expectOneCall("configd_mgmt_error_app_tag")
		->andReturnStringValue("APP_TAG_VALUE");

	mock_c()->expectOneCall("configd_mgmt_error_info")
		->andReturnPointerValue((void *)info_map);
}

void test_edit_config_fail()
{
	nc_rpc *test_rpc = NULL;
	nc_reply *reply = NULL;
	struct configd_ds *test_ds = NULL;

	struct configd_mgmt_error **errlist = calloc(
		1, sizeof(struct configd_mgmt_error *));
	errlist[0] = calloc(1, sizeof(struct configd_mgmt_error));

	char *test_xml =
		XML_RPC_START_TAG
		"  <nc:edit-config>"
		"    <nc:target>"
		"      <nc:candidate/>"
		"    </nc:target>"
		"    <nc:config>"
		"      <nc:system/>"
		"    </nc:config>"
		"  </nc:edit-config>"
		XML_RPC_END_TAG;

	mock_c()->expectOneCall("configd_sess_locked")
		->andReturnIntValue(0);
	mock_c()->expectOneCall("configd_edit_config_xml")
		->andReturnStringValue(NULL);

	mock_c()->expectOneCall("configd_error_num_mgmt_errors")
		->andReturnIntValue(1);
	mock_c()->expectOneCall("configd_error_mgmt_error_list")
		->andReturnPointerValue(errlist);
	mock_nc_err_from_mgmt_err_call(NO_INFO);
	mock_c()->expectOneCall("configd_error_free");

	test_rpc = nc_rpc_build(test_xml, NULL);

	reply = configd_ds_apply_rpc(test_ds, test_rpc);

	CHECK_EQUAL_C_INT(NC_REPLY_ERROR, nc_reply_get_type(reply));
	CHECK_EQUAL_C_STRING("MESSAGE_VALUE", nc_reply_get_errormsg(reply));

	free(errlist[0]);
	free(errlist);
}

// There are 2 ways that GET requests could in theory be invoked.  This test
// checks the one that seems to be used in NETCONF requests, and the one in
// the memory-checked tests checks the other path just be be on the safe side.
void test_get_fail_direct()
{
	nc_rpc *test_rpc = NULL;
	nc_reply *reply = NULL;
	struct configd_ds *test_ds = NULL;

	struct configd_mgmt_error **errlist = calloc(
		1, sizeof(struct configd_mgmt_error *));
	errlist[0] = calloc(1, sizeof(struct configd_mgmt_error));

	char *test_xml =
		XML_RPC_START_TAG
		"  <nc:get>"
		"    <nc:filter>"
		"      <nc:interface_state/>"
		"    </nc:filter>"
		"  </nc:get>"
		XML_RPC_END_TAG;

	mock_c()->expectOneCall("configd_get_schemas")
		->andReturnStringValue(NULL);

	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/interface_state")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tree_get_full_encoding_flags")
		->withStringParameters("path", "/interface_state")
		->andReturnStringValue(NULL);

	mock_c()->expectOneCall("configd_error_num_mgmt_errors")
		->andReturnIntValue(1);
	mock_c()->expectOneCall("configd_error_mgmt_error_list")
		->andReturnPointerValue(errlist);
	mock_nc_err_from_mgmt_err_call(NO_INFO);
	mock_c()->expectOneCall("configd_error_free");

	test_rpc = nc_rpc_build(test_xml, NULL);

	reply = configd_ds_get(test_ds, test_rpc);

	CHECK_EQUAL_C_INT(NC_REPLY_ERROR, nc_reply_get_type(reply));
	CHECK_EQUAL_C_STRING("MESSAGE_VALUE", nc_reply_get_errormsg(reply));

	free(errlist[0]);
	free(errlist);
}

void test_copy_config_fail()
{
	nc_rpc *test_rpc = NULL;
	nc_reply *reply = NULL;
	struct configd_ds *test_ds = NULL;

	struct configd_mgmt_error **errlist = calloc(
		1, sizeof(struct configd_mgmt_error *));
	errlist[0] = calloc(1, sizeof(struct configd_mgmt_error));

	char *test_xml =
		XML_RPC_START_TAG
		"  <nc:copy-config>"
		"    <nc:target>"
		"      <nc:candidate/>"
		"    </nc:target>"
		"    <nc:source>"
		"      <nc:config>"
		"        <nc:testleaf>value</nc:testleaf>"
		"      </nc:config>"
		"    </nc:source>"
		"  </nc:copy-config>"
		XML_RPC_END_TAG;

	mock_c()->expectOneCall("configd_sess_locked")
		->andReturnIntValue(0);

	// Returning NULL from configd_copy_config indicates failure ...
	mock_c()->expectOneCall("configd_copy_config")
		->andReturnStringValue(NULL);

	// Mock functions called by configd_ds_build_reply_error() so we get one
	// error back with TEST_MSG as the message content.
	mock_c()->expectOneCall("configd_error_num_mgmt_errors")
		->andReturnIntValue(1);
	mock_c()->expectOneCall("configd_error_mgmt_error_list")
		->andReturnPointerValue(errlist);
	mock_nc_err_from_mgmt_err_call(NO_INFO);
	mock_c()->expectOneCall("configd_error_free");

	test_rpc = nc_rpc_build(test_xml, NULL);

	// Call from as high up the calling stack as possible to show error makes
	// it this far.
	reply = configd_ds_apply_rpc(test_ds, test_rpc);

	// We only get access to type and message with existing libnetconf APIs,
	// so that's all we can check.  TEST_MSG is set up by the call to
	// mock_nc_err_from_mgmt_err_call()
	CHECK_EQUAL_C_INT(NC_REPLY_ERROR, nc_reply_get_type(reply));
	CHECK_EQUAL_C_STRING("MESSAGE_VALUE", nc_reply_get_errormsg(reply));

	free(errlist[0]);
	free(errlist);
}
