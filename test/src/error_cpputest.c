/*
 * Copyright (c) 2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <string.h>
#include <argz.h>
#include <envz.h>
#include <vyatta-util/map.h>
#include <vyatta-cfg/client/mgmt.h>

#include "configd_datastore.h"
#include "configd_path.h"

#include "CppUTest/TestHarness_c.h"
#include "CppUTestExt/MockSupport_c.h"
#include "CppUTest/MemoryLeakDetectorMallocMacros.h"

#include "netconf_test.h"

// The following definitions are designed to make the tests more readable by
// clearly showing what the various NULL values represent.

#define NULL_TAG NULL
#define NULL_TYPE NULL
#define NULL_SEVERITY NULL
#define NULL_APP_TAG NULL
#define NULL_PATH NULL
#define NULL_MESSAGE NULL

#define NULL_INFO NULL

#define NO_ERR_TEXT NULL
#define NO_FALLBACK_TEXT NULL

// To help make it clearer what the main target of the test is, and what is
// less relevant, some of the 'default' error field contents are defined here.
#define TYPE_APPLICATION "application"

#define TAG_MISSING_ELEM "missing-element"
#define TAG_OP_FAIL "operation-failed"

#define SEV_ERROR "error"

#define TEST_APP_TAG "TEST_APP_TAG"
#define TEST_MSG "TEST_MSG"
#define TEST_PATH "TEST_PATH"
#define TEST_SEV "TEST_SEV"
#define TEST_TAG "TEST_TAG"
#define TEST_TYPE "TEST_TYPE"

#define TEST_APP_TAG_2 "TEST_APP_TAG_2"
#define TEST_MSG_2 "TEST_MSG_2"
#define TEST_PATH_2 "TEST_PATH_2"
#define TEST_SEV_2 "TEST_SEV_2"
#define TEST_TAG_2 "TEST_TAG_2"
#define TEST_TYPE_2 "TEST_TYPE_2"

#define NO_ERRORS 0
#define ONE_ERROR 1
#define TWO_ERRORS 2

#define IS_MGMT_ERROR 1
#define NOT_MGMT_ERROR 0

TEST_GROUP_C_SETUP(error)
{
	// Allows us to see any errors in libnetconf.
	nc_callback_print(test_print);
}

TEST_GROUP_C_TEARDOWN(error)
{
	mock_c()->checkExpectations();

	// Clear any expectations etc before next test runs.
	mock_c()->clear();

	// In case we installed any for the test.
	mock_c()->removeAllComparatorsAndCopiers();
}

// mock_nc_err_from_mgmt_err_call
//
// Mock up suitable replies from vyatta-cfg APIs to populate a nc_err from
// a configd_error that contains mgmt_error info.  As it stands, we can only
// verify the message field here as libnetconf does not provide APIs for the
// other fields.  We test those via acceptance tests.
static void mock_nc_err_from_mgmt_err_call(const struct map *info_map) {

	mock_c()->expectOneCall("configd_mgmt_error_type")
		->andReturnStringValue(TEST_TYPE);
	mock_c()->expectOneCall("configd_mgmt_error_severity")
		->andReturnStringValue(TEST_SEV);
	mock_c()->expectOneCall("configd_mgmt_error_tag")
		->andReturnStringValue(TEST_TAG);
	mock_c()->expectOneCall("configd_mgmt_error_message")
		->andReturnStringValue(TEST_MSG);
	mock_c()->expectOneCall("configd_mgmt_error_path")
		->andReturnStringValue(TEST_PATH);
	mock_c()->expectOneCall("configd_mgmt_error_app_tag")
		->andReturnStringValue(TEST_APP_TAG);

	mock_c()->expectOneCall("configd_mgmt_error_info")
		->andReturnPointerValue((void *)info_map);
}

static void mock_second_nc_err_from_mgmt_err_call(const struct map *info_map) {

	mock_c()->expectOneCall("configd_mgmt_error_type")
		->andReturnStringValue(TEST_TYPE_2);
	mock_c()->expectOneCall("configd_mgmt_error_severity")
		->andReturnStringValue(TEST_SEV_2);
	mock_c()->expectOneCall("configd_mgmt_error_tag")
		->andReturnStringValue(TEST_TAG_2);
	mock_c()->expectOneCall("configd_mgmt_error_message")
		->andReturnStringValue(TEST_MSG_2);
	mock_c()->expectOneCall("configd_mgmt_error_path")
		->andReturnStringValue(TEST_PATH_2);
	mock_c()->expectOneCall("configd_mgmt_error_app_tag")
		->andReturnStringValue(TEST_APP_TAG_2);

	mock_c()->expectOneCall("configd_mgmt_error_info")
		->andReturnPointerValue((void *)info_map);
}

static struct configd_mgmt_error **mock_configd_ds_build_reply_error(
	int num_errors,
	const struct map *info_map)
{
	int i = 0;

	struct configd_mgmt_error **errlist = calloc(
		num_errors, sizeof(struct configd_mgmt_error *));

	for (i = 0; i < num_errors; i++) {
		errlist[i] = calloc(1, sizeof(struct configd_mgmt_error));
	}

	mock_c()->expectOneCall("configd_error_num_mgmt_errors")
		->andReturnIntValue(num_errors);
	mock_c()->expectOneCall("configd_error_is_mgmt_error")
		->andReturnIntValue(1);
	mock_c()->expectOneCall("configd_error_mgmt_error_list")
		->andReturnPointerValue(errlist);

	mock_nc_err_from_mgmt_err_call(info_map);

	return errlist;
}

static void mock_create_mgmt_error_calls(
	int num_errors,
	int is_mgmt_error,
	struct configd_mgmt_error ** errlist)
{
	mock_c()->expectOneCall("configd_error_num_mgmt_errors")
		->andReturnIntValue(num_errors);
	mock_c()->expectOneCall("configd_error_is_mgmt_error")
		->andReturnIntValue(is_mgmt_error);
	mock_c()->expectOneCall("configd_error_mgmt_error_list")
		->andReturnPointerValue(errlist);
}



static const struct map *get_test_info_map()
{
	const struct map *info_map = NULL;
	char *argz = NULL;
	size_t argz_len = 0;

	argz_create_sep("", 0, &argz, &argz_len);
	envz_add(&argz, &argz_len, "bad-element", "BAD-ELEM INFO");
	envz_add(&argz, &argz_len, "bad-attribute", "BAD-ATTR INFO");
	envz_add(&argz, &argz_len, "bad-namespace", "BAD-NS INFO");
	envz_add(&argz, &argz_len, "session-id", "SID INFO");
	envz_add(&argz, &argz_len, "unhandled", "UNHANDLED");

	info_map = map_new(argz, argz_len);
	return info_map;
}

// FAIL_TEXT_C() exits the function, so it's impossible to free the memory
// allocated by asprintf here.  Also, if you do, then in some test failure
// cases, the free w/o allocate error is triggered instead of the real failure
// so debug is harder.
// Given memory leak is only for duration of test, it seems preferable to
// allow it!
static void check_nc_reply_field(
	const char *rep_txt,
	const char *elem_name,
	const char *elem_content)
{
	char *match_str = NULL;
	char *err_str = NULL;

	if (elem_content != NULL) {
		asprintf(&match_str, "<error-%s>%s</error-%s>",
			elem_name, elem_content, elem_name);
		if (strstr(rep_txt, match_str) == NULL) {
			asprintf(&err_str, "\nFailed to find: %s\nFull reply:\n%s\n",
				match_str, rep_txt);
			FAIL_TEXT_C(err_str);
		}
		return;
	}

	asprintf(&match_str, "<error-%s>", elem_name);
	if (strstr(rep_txt, match_str) != NULL) {
		asprintf(&err_str, "Unexpectedly found: %s\nFull reply:\n%s\n",
			match_str, rep_txt);
		FAIL_TEXT_C(err_str);
	}
}

static void check_nc_reply(
	nc_reply *rep,
	const char *type,
	const char *tag,
	const char *sev,
	const char *msg,
	const char *path,
	const char *app_tag)
{
	const char *rep_txt = nc_rpc_dump(rep);

	check_nc_reply_field(rep_txt, "type", type);
	check_nc_reply_field(rep_txt, "tag", tag);
	check_nc_reply_field(rep_txt, "severity", sev);
	check_nc_reply_field(rep_txt, "message", msg);
	check_nc_reply_field(rep_txt, "path", path);
	check_nc_reply_field(rep_txt, "app-tag", app_tag);
}

// nc_err_from_mgmt_err() tests.
//
// These check this function correctly handles different subsets of params
// in a given error, including presence or absence of INFO elements.

TEST_C(error, nc_err_from_mgmt_err_no_info)
{
	struct configd_mgmt_error me = { 0 };
	struct nc_err *err;
	const char *val = NULL;

	mock_nc_err_from_mgmt_err_call(NO_INFO);

	err = nc_err_from_cfg_mgmt_err(&me);

	val = nc_err_get(err, NC_ERR_PARAM_MSG);
	CHECK_EQUAL_C_STRING(TEST_MSG, val);

	val = nc_err_get(err, NC_ERR_PARAM_TYPE);
	CHECK_EQUAL_C_STRING(TEST_TYPE, val);

	val = nc_err_get(err, NC_ERR_PARAM_PATH);
	CHECK_EQUAL_C_STRING(TEST_PATH, val);

	val = nc_err_get(err, NC_ERR_PARAM_SEVERITY);
	CHECK_EQUAL_C_STRING(TEST_SEV, val);

	val = nc_err_get(err, NC_ERR_PARAM_TAG);
	CHECK_EQUAL_C_STRING(TEST_TAG, val);

	val = nc_err_get(err, NC_ERR_PARAM_APPTAG);
	CHECK_EQUAL_C_STRING(TEST_APP_TAG, val);
}

TEST_C(error, nc_err_from_mgmt_err_info)
{
	struct configd_mgmt_error me = { 0 };
	struct nc_err *err;
	const char *val = NULL;

	mock_nc_err_from_mgmt_err_call(get_test_info_map());

	err = nc_err_from_cfg_mgmt_err(&me);

	val = nc_err_get(err, NC_ERR_PARAM_INFO_BADELEM);
	CHECK_EQUAL_C_STRING("BAD-ELEM INFO", val);

	val = nc_err_get(err, NC_ERR_PARAM_INFO_BADATTR);
	CHECK_EQUAL_C_STRING("BAD-ATTR INFO", val);

	val = nc_err_get(err, NC_ERR_PARAM_INFO_BADNS);
	CHECK_EQUAL_C_STRING("BAD-NS INFO", val);

	val = nc_err_get(err, NC_ERR_PARAM_INFO_SID);
	CHECK_EQUAL_C_STRING("SID INFO", val);
}

TEST_C(error, nc_err_from_mgmt_err_some_fields_missing)
{
	// Need to modify mock_nc_err_from_mgmt_err_call to only set some fields.
	//FAIL_TEXT_C("TBD");
}

// This set of tests checks handling of basic errors, ie when we don't have
// a management error, or if extraction of it fails in some way.
TEST_C(error, cfgd_basic_nc_err_with_err_text)
{
	nc_reply *rep = configd_ds_basic_nc_error(
		NC_ERR_MISSING_ELEM, "some message", "fallback message");

	check_nc_reply(rep,
		TYPE_APPLICATION,
		TAG_MISSING_ELEM,
		SEV_ERROR,
		"some message",
		NULL_PATH,
		NULL_APP_TAG);
}

TEST_C(error, cfgd_basic_nc_err_with_fallback_text)
{
	nc_reply *rep = configd_ds_basic_nc_error(
		NC_ERR_MISSING_ELEM, NO_ERR_TEXT, "fallback message");

	check_nc_reply(rep,
		TYPE_APPLICATION,
		TAG_MISSING_ELEM,
		SEV_ERROR,
		"fallback message",
		NULL_PATH,
		NULL_APP_TAG);
}

TEST_C(error, cfgd_basic_nc_err_with_no_text)
{
	nc_reply *rep = configd_ds_basic_nc_error(
		NC_ERR_MISSING_ELEM, NO_ERR_TEXT, NO_FALLBACK_TEXT);

	check_nc_reply(rep,
		TYPE_APPLICATION,
		TAG_MISSING_ELEM,
		SEV_ERROR,
		"Unspecified config system error",
		NULL_PATH,
		NULL_APP_TAG);
}

TEST_C(error, build_reply_no_errors)
{
	struct configd_error ce = { .source = NULL, .text = "some msg" };
	nc_reply *rep;

	mock_c()->expectOneCall("configd_error_num_mgmt_errors")
		->andReturnIntValue(0);

	rep = configd_ds_build_reply_error(&ce, NC_ERR_OP_FAILED, "fallback msg");

	check_nc_reply(rep,
		TYPE_APPLICATION,
		TAG_OP_FAIL,
		SEV_ERROR,
		"some msg",
		NULL_PATH,
		NULL_APP_TAG);
}

TEST_C(error, build_reply_not_mgmt_error)
{
	// This time text is null to test fallback case.
	struct configd_error ce = { .source = NULL, .text = NULL };
	nc_reply *rep;

	mock_c()->expectOneCall("configd_error_num_mgmt_errors")
		->andReturnIntValue(1);
	mock_c()->expectOneCall("configd_error_is_mgmt_error")
		->andReturnIntValue(0);

	rep = configd_ds_build_reply_error(&ce, NC_ERR_OP_FAILED, "fallback msg");

	check_nc_reply(rep,
		TYPE_APPLICATION,
		TAG_OP_FAIL,
		SEV_ERROR,
		"fallback msg",
		NULL_PATH,
		NULL_APP_TAG);
}

TEST_C(error, build_reply_null_error_list)
{
	struct configd_error ce = { .source = NULL, .text = "some msg" };
	nc_reply *rep;

	mock_create_mgmt_error_calls(ONE_ERROR, IS_MGMT_ERROR, NULL);

	rep = configd_ds_build_reply_error(&ce, NC_ERR_OP_FAILED, "fallback msg");

	check_nc_reply(rep,
		TYPE_APPLICATION,
		TAG_OP_FAIL,
		SEV_ERROR,
		"some msg",
		NULL_PATH,
		NULL_APP_TAG);
}

TEST_C(error, build_reply_error_is_null)
{
	// text null to test fallback case this time
	struct configd_error ce = { .source = NULL, .text = NULL };
	nc_reply *rep;
	struct configd_mgmt_error **errlist = calloc(
		1, sizeof(struct configd_mgmt_error *));

	mock_create_mgmt_error_calls(ONE_ERROR, IS_MGMT_ERROR, errlist);

	rep = configd_ds_build_reply_error(&ce, NC_ERR_OP_FAILED, "fallback msg");

	check_nc_reply(rep,
		TYPE_APPLICATION,
		TAG_OP_FAIL,
		SEV_ERROR,
		"fallback msg",
		NULL_PATH,
		NULL_APP_TAG);

	free(errlist);
}

TEST_C(error, build_reply_single_error)
{
	struct configd_error ce = { .source = NULL, .text = NULL };
	struct configd_mgmt_error **errlist = NULL;
	nc_reply *rep;

	errlist = mock_configd_ds_build_reply_error(1, NULL_INFO);

	rep = configd_ds_build_reply_error(&ce, NC_ERR_OP_FAILED, "fallback msg");

	//barf(); // Pass in num_errors not values, create free fn for errlist.
	check_nc_reply(rep,
		TEST_TYPE, TEST_TAG, TEST_SEV, TEST_MSG, TEST_PATH, TEST_APP_TAG);

	free(errlist[0]);
	free(errlist);
}

TEST_C(error, build_reply_multiple_errors)
{
	struct configd_error ce = { .source = NULL, .text = NULL };
	nc_reply *rep;

	struct configd_mgmt_error **errlist = calloc(
		2, sizeof(struct configd_mgmt_error *));
	errlist[0] = calloc(1, sizeof(struct configd_mgmt_error));
	errlist[1] = calloc(1, sizeof(struct configd_mgmt_error));

	mock_create_mgmt_error_calls(TWO_ERRORS, IS_MGMT_ERROR, errlist);
	mock_nc_err_from_mgmt_err_call(NULL_INFO);
	mock_second_nc_err_from_mgmt_err_call(NULL_INFO);

	rep = configd_ds_build_reply_error(&ce, NC_ERR_OP_FAILED, "fallback msg");

	check_nc_reply(rep,
		TEST_TYPE, TEST_TAG, TEST_SEV, TEST_MSG, TEST_PATH, TEST_APP_TAG);
	check_nc_reply(rep,
		TEST_TYPE_2, TEST_TAG_2, TEST_SEV_2,
		TEST_MSG_2, TEST_PATH_2, TEST_APP_TAG_2);

	free(errlist[0]);
	free(errlist[1]);
	free(errlist);
}

// The next set of tests verifies the handling of errors for certain NETCONF
// operations that may return errors in mgmt_error form.
//
// Frustratingly, libnetconf API only gives us access to the <message> field.
// Testing <message> shows that we must have processed the mocked reply
// from configd_validate() as a mgmt_error or we would get the generic
// 'validation failed ...' message instead so that has to do for now.

TEST_C(error, validate_fail)
{
	nc_rpc *test_rpc = NULL;
	nc_reply *reply = NULL;
	struct configd_ds *test_ds = NULL;

	struct configd_mgmt_error **errlist = calloc(
		1, sizeof(struct configd_mgmt_error *));
	errlist[0] = calloc(1, sizeof(struct configd_mgmt_error));

	char *test_xml =
		XML_RPC_START_TAG
		"  <nc:validate>"
		"    <nc:source>"
		"      <nc:candidate/>"
		"    </nc:source>"
		"  </nc:validate>"
		XML_RPC_END_TAG;

	mock_c()->expectOneCall("configd_sess_exists")
		->andReturnIntValue(1);
	mock_c()->expectOneCall("configd_sess_changed")
		->andReturnIntValue(1);

	// Returning NULL from configd_validate indicates failure ...
	mock_c()->expectOneCall("configd_validate")
		->andReturnStringValue(NULL);

	// Mock functions called by configd_ds_build_reply_error() so we get one
	// error back with TEST_MSG as the message content.
	mock_create_mgmt_error_calls(ONE_ERROR, IS_MGMT_ERROR, errlist);
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
	CHECK_EQUAL_C_STRING(TEST_MSG, nc_reply_get_errormsg(reply));

	free(errlist[0]);
	free(errlist);
}

TEST_C(error, commit_fail)
{
	nc_rpc *test_rpc = NULL;
	nc_reply *reply = NULL;
	struct configd_ds *test_ds = NULL;

	struct configd_mgmt_error **errlist = calloc(
		1, sizeof(struct configd_mgmt_error *));
	errlist[0] = calloc(1, sizeof(struct configd_mgmt_error));

	// Default target is RUNNING.
	char *test_xml =
		XML_RPC_START_TAG
		"  <nc:commit/>"
		XML_RPC_END_TAG;

	mock_c()->expectOneCall("configd_confirmed_commit")
		->andReturnStringValue(NULL);

	mock_create_mgmt_error_calls(ONE_ERROR, IS_MGMT_ERROR, errlist);
	mock_nc_err_from_mgmt_err_call(NO_INFO);
	mock_c()->expectOneCall("configd_error_free");

	test_rpc = nc_rpc_build(test_xml, NULL);

	reply = configd_ds_apply_rpc(test_ds, test_rpc);

	CHECK_EQUAL_C_INT(NC_REPLY_ERROR, nc_reply_get_type(reply));
	CHECK_EQUAL_C_STRING(TEST_MSG, nc_reply_get_errormsg(reply));

	free(errlist[0]);
	free(errlist);
}

TEST_C(error, get_config_fail)
{
	nc_rpc *test_rpc = NULL;
	nc_reply *reply = NULL;
	struct configd_ds *test_ds = NULL;

	struct configd_mgmt_error **errlist = calloc(
		1, sizeof(struct configd_mgmt_error *));
	errlist[0] = calloc(1, sizeof(struct configd_mgmt_error));

	char *test_xml =
		XML_RPC_START_TAG
		"  <nc:get-config>"
		"    <nc:source>"
		"      <nc:running/>"
		"    </nc:source>"
		"    <nc:filter>"
		"      <nc:interfaces/>"
		"    </nc:filter>"
		"  </nc:get-config>"
		XML_RPC_END_TAG;

	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/interfaces")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tree_get_encoding_flags")
		->withStringParameters("path", "/interfaces")
		->andReturnStringValue(NULL);

	mock_create_mgmt_error_calls(ONE_ERROR, IS_MGMT_ERROR, errlist);
	mock_nc_err_from_mgmt_err_call(NO_INFO);
	mock_c()->expectOneCall("configd_error_free");

	test_rpc = nc_rpc_build(test_xml, NULL);

	reply = configd_ds_apply_rpc(test_ds, test_rpc);

	CHECK_EQUAL_C_INT(NC_REPLY_ERROR, nc_reply_get_type(reply));
	CHECK_EQUAL_C_STRING(TEST_MSG, nc_reply_get_errormsg(reply));

	free(errlist[0]);
	free(errlist);}

TEST_C(error, get_fail)
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

	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/interface_state")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tree_get_full_encoding_flags")
		->withStringParameters("path", "/interface_state")
		->andReturnStringValue(NULL);

	mock_create_mgmt_error_calls(ONE_ERROR, IS_MGMT_ERROR, errlist);
	mock_nc_err_from_mgmt_err_call(NO_INFO);
	mock_c()->expectOneCall("configd_error_free");

	test_rpc = nc_rpc_build(test_xml, NULL);

	reply = configd_ds_apply_rpc(test_ds, test_rpc);

	CHECK_EQUAL_C_INT(NC_REPLY_ERROR, nc_reply_get_type(reply));
	CHECK_EQUAL_C_STRING(TEST_MSG, nc_reply_get_errormsg(reply));

	free(errlist[0]);
	free(errlist);
}
