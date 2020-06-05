/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <string.h>
#include <argz.h>
#include <envz.h>
#include <vyatta-util/map.h>

#include "configd_datastore.h"
#include "configd_path.h"

#include "CppUTest/TestHarness_c.h"
#include "CppUTestExt/MockSupport_c.h"
#include "CppUTest/MemoryLeakDetectorMallocMacros.h"

#include "netconf_test.h"

#define RETURN_ALL_PATH ""
#define NO_PATH "NO_PATH"

static struct map *map_with_tag = NULL;
static char *argz = NULL;

TEST_GROUP_C_SETUP(filter)
{
	// Allows us to see any errors in libnetconf.
	nc_callback_print(test_print);

	// Create map with 'tag=1' for us with mocking configd_tmpl_get().
	size_t argz_len = 0;

	if (argz_create_sep("", 0, &argz, &argz_len)) {
		FAIL_TEXT_C("Failed to call argz_create_sep()");
	}
	if (envz_add(&argz, &argz_len, "tag", "1")) {
		free(argz);
		FAIL_TEXT_C("Failed to call envz_add()");
	}
	map_with_tag = map_new(argz, argz_len);
	if (map_with_tag == NULL) {
		free(argz);
		FAIL_TEXT_C("Failed to call map_new()");
	}
}

TEST_GROUP_C_TEARDOWN(filter)
{
	mock_c()->checkExpectations();

	// Clear any expectations etc before next test runs.
	mock_c()->clear();

	// In case we installed any for the test.
	mock_c()->removeAllComparatorsAndCopiers();

	// NB: we don't free argz or map_with_tag as the memory leak checker
	//     complains they weren't allocated.  Not entirely sure that is
	//     correct, but as this is TEST code, we can live with it (-:
}

void check_filter_path(char *test_xml, char *exp)
{
	nc_rpc *test_rpc = NULL;
	char *act = NULL;

	test_rpc = nc_rpc_build(test_xml, NULL);

	act = configd_convert_filter_to_config_path(test_rpc, NULL);

	CHECK_EQUAL_C_STRING(exp, act);

	free(act);
}

// First test cases where we will get empty path back as RPC is either
// malformed, or requesting full tree.

TEST_C(filter, rpc_not_get_or_get_config)
{
	check_filter_path(
		XML_RPC_START_TAG
		"  <nc:unknown>"
		"  </nc:unknown>"
		XML_RPC_END_TAG,
		RETURN_ALL_PATH);
}

TEST_C(filter, rpc_with_multiple_filter_elements)
{
	check_filter_path(
		XML_RPC_START_TAG
		"  <nc:get>"
		"    <nc:filter type=\"subtree\">"
		"      <nc:policy/>"
		"    </nc:filter>"
		"    <nc:filter type=\"subtree\">"
		"      <nc:system/>"
		"    </nc:filter>"
		"  </nc:get>"
		XML_RPC_END_TAG,
		RETURN_ALL_PATH);
}

TEST_C(filter, rpc_with_non_filter_element)
{
	check_filter_path(
		XML_RPC_START_TAG
		"  <nc:get>"
		"    <nc:notfilter type=\"subtree\">"
		"      <nc:policy/>"
		"    </nc:notfilter>"
		"  </nc:get>"
		XML_RPC_END_TAG,
		RETURN_ALL_PATH);
}

// For XPATH filter type, we don't parse filter.
TEST_C(filter, rpc_with_xpath_filter)
{
	check_filter_path(
		XML_RPC_START_TAG
		"  <nc:get>"
		"    <nc:filter type=\"xpath\">"
		"      <nc:policy/>"
		"    </nc:filter>"
		"  </nc:get>"
		XML_RPC_END_TAG,
		RETURN_ALL_PATH);
}

// Should return NO data
TEST_C(filter, rpc_with_empty_filter)
{
	check_filter_path(
		XML_RPC_START_TAG
		"  <nc:get>"
		"    <nc:filter type=\"subtree\">"
		"    </nc:filter>"
		"  </nc:get>"
		XML_RPC_END_TAG,
		NO_PATH);
}

// Should return ALL data
TEST_C(filter, rpc_with_no_filter)
{
	check_filter_path(
		XML_RPC_START_TAG
		"  <nc:get/>"
		XML_RPC_END_TAG,
		RETURN_ALL_PATH);
}

TEST_C(filter, rpc_with_no_filter_type)
{
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/policy")
		->andReturnStringValue(MAP_NOT_TAG);

	check_filter_path(
		XML_RPC_START_TAG
		"  <nc:get>"
		"    <nc:filter>"
		"      <nc:policy/>"
		"    </nc:filter>"
		"  </nc:get>"
		XML_RPC_END_TAG,
		"/policy");
}

TEST_C(filter, rpc_with_subtree_filter_type)
{
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/policy")
		->andReturnStringValue(MAP_NOT_TAG);

	check_filter_path(
		XML_RPC_START_TAG
		"  <nc:get>"
		"    <nc:filter type=\"subtree\">"
		"      <nc:policy/>"
		"    </nc:filter>"
		"  </nc:get>"
		XML_RPC_END_TAG,
		"/policy");
}

// Now test valid filters.  Terms such as containment, selection, content-match
// are defined in RFC 6241 (NETCONF).

// Containment + selection nodes (containers)
TEST_C(filter, rpc_get_selection_node_single_tag)
{
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/policy")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/policy/qos")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/policy/qos/state")
		->andReturnStringValue(MAP_NOT_TAG);

	check_filter_path(
		XML_RPC_GET_SUBTREE_START_TAG
		"<nc:policy xmlns=\"urn:vyatta.com:mgmt:vyatta-policy-qos:1\">"
		"  <nc:qos>"
		"    <nc:state/>"
		"  </nc:qos>"
		"</nc:policy>"
		XML_RPC_GET_SUBTREE_END_TAG,
		"/policy/qos/state");
}

// 'state' has whitespace-only content, so this is a selection node, not
// content match.
TEST_C(filter, rpc_get_selection_node_paired_tags)
{
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/policy")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/policy/qos")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/policy/qos/state")
		->andReturnStringValue(MAP_NOT_TAG);

	check_filter_path(
		XML_RPC_GET_SUBTREE_START_TAG
		"<nc:policy xmlns=\"urn:vyatta.com:mgmt:vyatta-policy-qos:1\">"
		"  <nc:qos>"
		"    <nc:state>   </nc:state>"
		"  </nc:qos>"
		"</nc:policy>"
		XML_RPC_GET_SUBTREE_END_TAG,
		"/policy/qos/state");
}

// NETCONFD has no concept of the node type (container / list / leaf), nor
// whether a node / element is a list key.  We list them out here as we need
// to consider in the different cases what we would need the path to be and
// test to check it is correct in all cases.

// Here we've got 'ifname' as an attribute.  Noting that for YANG, we don't
// have attributes, and that even if we did, we would be returning multiple
// children of dataplane (potentially), we stop at dataplane.
TEST_C(filter, rpc_get_attribute_match_node)
{
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/interfaces")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/interfaces/dataplane")
		->andReturnStringValue((const char *)map_with_tag);

	check_filter_path(
		XML_RPC_GET_SUBTREE_START_TAG
		"<nc:interfaces xmlns=\"urn:vyatta.com:mgmt:vyatta-interfaces:1\">"
		"  <nc:dataplane nc:ifname=\"dp0s1\"/>"
		"</nc:interfaces>"
		XML_RPC_GET_SUBTREE_END_TAG,
		"/interfaces/dataplane");
}

// Here we have specified a content match element.  In this case we will
// want siblings returned, so path stops at parent (dataplane).
TEST_C(filter, rpc_get_content_match_node)
{
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/interfaces")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/interfaces/dataplane")
		->andReturnStringValue((const char *)map_with_tag);

	check_filter_path(
		XML_RPC_GET_SUBTREE_START_TAG
		"<nc:interfaces xmlns=\"urn:vyatta.com:mgmt:vyatta-interfaces:1\">"
		"  <nc:dataplane>"
		"    <nc:tagnode>dp0s1</nc:tagnode>"
		"  </nc:dataplane>"
		"</nc:interfaces>"
		XML_RPC_GET_SUBTREE_END_TAG,
		"/interfaces/dataplane");
}

// CONFIG (just for a change).  Here we have multiple elements at one level,
// one of which has content.
TEST_C(filter, rpc_get_config_specific_elements)
{
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/system")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/system/login")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/system/login/user")
		->andReturnStringValue((const char *)map_with_tag);

	check_filter_path(
		XML_RPC_GET_CFG_SUBTREE_START_TAG
		"<nc:system xmlns=\"urn:vyatta.com:mgmt:vyatta-system:1\">"
		"  <nc:login>"
		"    <nc:user>"
		"      <nc:name>fred</nc:name>"
		"      <nc:group/>"
		"    </nc:user>"
		"  </nc:login>"
		"</nc:system>"
		XML_RPC_GET_CFG_SUBTREE_END_TAG,
		"/system/login/user");
}

// Now 'get' not 'get-config', and no content for <name>.
TEST_C(filter, rpc_get_specific_elements)
{
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/system")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/system/login")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/system/login/user")
		->andReturnStringValue((const char *)map_with_tag);

	check_filter_path(
		XML_RPC_GET_SUBTREE_START_TAG
		"<nc:system xmlns=\"urn:vyatta.com:mgmt:vyatta-system:1\">"
		"  <nc:login>"
		"    <nc:user>"
		"      <nc:name/>"
		"      <nc:group/>"
		"    </nc:user>"
		"  </nc:login>"
		"</nc:system>"
		XML_RPC_GET_SUBTREE_END_TAG,
		"/system/login/user");
}

// This is the one test that exercises is_list_node().  Others may return
// map_with_tag, but they are cases where the multiple_element check will
// cause the path construction to stop before the next element is added.
// Only here does returning map_with_tag impact the result.
TEST_C(filter, rpc_get_specific_non_tagnode_element)
{
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/system")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/system/login")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/system/login/user")
		->andReturnStringValue((const char *)map_with_tag);

	check_filter_path(
		XML_RPC_GET_SUBTREE_START_TAG
		"<nc:system xmlns=\"urn:vyatta.com:mgmt:vyatta-system:1\">"
		"  <nc:login>"
		"    <nc:user>"
		"      <nc:group/>"
		"    </nc:user>"
		"  </nc:login>"
		"</nc:system>"
		XML_RPC_GET_SUBTREE_END_TAG,
		"/system/login/user");
}

// Even if the multiple subtrees are for the same node name, safer to stop at
// node above.
TEST_C(filter, rpc_get_multiple_subtrees)
{
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/system")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/system/login")
		->andReturnStringValue(MAP_NOT_TAG);

	check_filter_path(
		XML_RPC_GET_SUBTREE_START_TAG
		"<nc:system xmlns=\"urn:vyatta.com:mgmt:vyatta-system:1\">"
		"  <nc:login>"
		"    <nc:user>"
		"      <nc:name>fred</nc:name>"
		"      <nc:group/>"
		"    </nc:user>"
		"    <nc:user>"
		"      <nc:name>wilma</nc:name>"
		"      <nc:level/>"
		"      <nc:full-name/>"
		"    </nc:user>"
		"  </nc:login>"
		"</nc:system>"
		XML_RPC_GET_SUBTREE_END_TAG,
		"/system/login");
}

TEST_C(filter, rpc_get_multiple_subtrees_divergent_paths)
{
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/system")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/system/login")
		->andReturnStringValue(MAP_NOT_TAG);

	check_filter_path(
		XML_RPC_GET_SUBTREE_START_TAG
		"<nc:system xmlns=\"urn:vyatta.com:mgmt:vyatta-system:1\">"
		"  <nc:login>"
		"    <nc:user>"
		"      <nc:name>fred</nc:name>"
		"      <nc:group/>"
		"    </nc:user>"
		"    <nc:superuser>"
		"      <nc:name>wilma</nc:name>"
		"      <nc:level/>"
		"      <nc:full-name/>"
		"    </nc:superuser>"
		"  </nc:login>"
		"</nc:system>"
		XML_RPC_GET_SUBTREE_END_TAG,
		"/system/login");
}

