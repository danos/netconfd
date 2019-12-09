/*
 * Copyright (c) 2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This file contains functions for extracting RPC
 * attributes
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <vyatta-cfg/client/mgmt.h>
#include <vyatta-util/map.h>

#include "configd_path.h"

/*
 * get_element
 *
 * Returns named element.
 * returns NULL if not found
 */
static xmlNode *get_element(const char *name, xmlNode *node)
{
	xmlNode *elem = NULL;

	elem = get_first_element(node);
	while (elem && strcmp(name, (char *)elem->name)) {
		elem = get_first_element(elem->next);
	}
	if (elem == NULL) {
		return NULL;
	}

	return elem;
}

/*
 * get_element_value
 *
 * Returns an XML element's attribute value
 * returning NULL if not present
 *
 */
static char *get_element_value(xmlNode *node)
{
	xmlNode *elem = NULL;
	for (elem = node->children; elem != NULL; elem = elem->next) {
		if (!strcmp("text", (char *)elem->name)) {
			return configd_strdup((char *)elem->content);
		}
	}
	return NULL;
}

/*
 * configd_get_rpc_value_internal
 *
 * Attempt to extract a named attribute's value from the RPC, if present.
 * if the rpc_name and attribute name do not match, returns NULL
 */
char *configd_get_rpc_value_internal(
	const char *rpc_name,
	const char *attr_name,
	const nc_rpc *rpc)
{
	xmlNode *root = NULL, *attr = NULL;
	xmlDoc *doc = NULL;
	char *val = NULL;

	/*
	 * Apparently required to initialise the library and check the version
	 * is as expected.
	 */
	LIBXML_TEST_VERSION;

	if (rpc == NULL) {
	    return NULL;
	}

	unsigned char *op_content = (unsigned char *)nc_rpc_get_op_content(rpc);

	doc = xmlParseDoc(op_content);
	if (doc == NULL) {
		return NULL;
	}

	/*Get the root element node */
	root = xmlDocGetRootElement(doc);

	if ( strcmp(rpc_name, (char *)root->name)) {
	    xmlFreeDoc(doc);
	    xmlCleanupParser();
	    return NULL;
	}

	attr = get_element(attr_name, root->children);
	if (attr == NULL) {
		xmlFreeDoc(doc);
		xmlCleanupParser();
		return NULL;
	}


	val = get_element_value(attr);

	/*free the document */
	xmlFreeDoc(doc);

	/*
	 *Free the global variables that may
	 *have been allocated by the parser.
	 */
	xmlCleanupParser();

	return val;
}


/*
 * configd_get_rpc_value_internal
 *
 * Attempt to extract a named attributes value from the RPC, if present.
 * if the rpc_name and attribute name do not match, returns empty string ""
 */
char *configd_get_rpc_value(
	const char *rpc_name,
	const char *attr_name,
	const nc_rpc *rpc)
{
	char *val = NULL;

	val = configd_get_rpc_value_internal(rpc_name, attr_name, rpc);

	if (val == NULL) {
		val = configd_strdup("");
	}

	return val;
}

/*
 * configd_rpc_value_exists
 *
 * Look for the named XML element in the named RPC
 * if found, return 1
 * otherwise return 0
 */
int configd_rpc_value_exists(
	const char *rpc_name,
	const char *attr_name,
	const nc_rpc *rpc)
{
	xmlNode *root = NULL, *attr = NULL;
	xmlDoc *doc = NULL;

	/*
	 * Apparently required to initialise the library and check the version
	 * is as expected.
	 */
	LIBXML_TEST_VERSION;

	if (rpc == NULL) {
	    return 0;
	}

	unsigned char *op_content = (unsigned char *)nc_rpc_get_op_content(rpc);

	doc = xmlParseDoc(op_content);
	if (doc == NULL) {
		return 0;
	}

	/*Get the root element node */
	root = xmlDocGetRootElement(doc);

	if ( strcmp(rpc_name, (char *)root->name)) {
		xmlFreeDoc(doc);
		xmlCleanupParser();
		return 0;
	}

	attr = get_element(attr_name, root->children);
	if (attr == NULL) {
		xmlFreeDoc(doc);
		xmlCleanupParser();
		return 0;
	}


	/*free the document */
	xmlFreeDoc(doc);

	/*
	 *Free the global variables that may
	 *have been allocated by the parser.
	 */
	xmlCleanupParser();

	return 1;
}
