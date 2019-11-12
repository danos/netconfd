/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <string.h>

#include "configd_datastore.h"
#include "configd_path.h"

#include "CppUTest/TestHarness_c.h"
#include "CppUTestExt/MockSupport_c.h"

#include "filter_no_memcheck_cpputest.h"

#define XML_RPC_GET_SUBTREE_START_TAG \
	"<?xml version=\"1.0\" encoding=\"UTF-8\"?>" \
	"<nc:rpc xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" " \
	"    message-id=\"urn:uuid:f5a7861b-43ed-47f5-93dc-fbc30e1c4720\">" \
	"  <nc:get>" \
	"    <nc:filter type=\"subtree\">"
#define XML_RPC_GET_SUBTREE_END_TAG \
	"    </nc:filter>" \
	"  </nc:get>" \
	"</nc:rpc>"

// Finally, check the output from our filter evaluation is passed on to
// the configd API correctly.
char *test_rpc_selection_single_tag = ""
       "      <nc:policy xmlns=\"urn:vyatta.com:mgmt:vyatta-policy-qos:1\">"
       "        <nc:qos>"
       "          <nc:state/>"
       "        </nc:qos>"
       "      </nc:policy>";

static const char *MAP_NOT_TAG = NULL;

void test_check_configd_gets_correct_filter(void)
{
	char *fullenc_retval = NULL;
	char *schema_retval = NULL;
	struct configd_ds *cfgd_ds;
	nc_reply *reply = NULL;
	char test_rpc[1000];
	nc_rpc *rpc = NULL;

	snprintf(test_rpc, sizeof(test_rpc), "%s%s%s\n",
			 XML_RPC_GET_SUBTREE_START_TAG,
			 test_rpc_selection_single_tag,
			 XML_RPC_GET_SUBTREE_END_TAG);
	rpc = nc_rpc_build(test_rpc, NULL);

	// configd_get_schemas() would malloc this.
	schema_retval = (char *)malloc(32);

	mock_c()->expectOneCall("configd_get_schemas")
		->andReturnStringValue(schema_retval);

	// configd_get_schemas() would malloc this.
	fullenc_retval = (char *)malloc(32);
	strncpy(fullenc_retval, "<data>foo</data>", 31);

	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/policy")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/policy/qos")
		->andReturnStringValue(MAP_NOT_TAG);
	mock_c()->expectOneCall("configd_tmpl_get")
		->withStringParameters("cpath", "/policy/qos/state")
		->andReturnStringValue(MAP_NOT_TAG);

	// This will show that our filter is being correctly passed on ...
	mock_c()->expectOneCall("configd_tree_get_full_encoding_flags")
		->withStringParameters("path", "/policy/qos/state")
		->andReturnStringValue(fullenc_retval);
	mock_c()->expectOneCall("configd_error_free");

	// Need to set up RPC correctly so we don't return early in
	// configd_ds_get_all()
	cfgd_ds = new_configd_ds();
	reply = configd_ds_get(
		cfgd_ds,
		rpc);
	nc_reply_free(reply);
}
