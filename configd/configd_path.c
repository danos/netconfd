/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * This file contains functions for extracting a 'configd-friendly' path from
 * the NETCONF subtree filter that can be passed on to GetTree[Full](), thus
 * reducing the amount of unnecessary information gathering that configd
 * would otherwise do.
 *
 * As YANG and configd paths are different (configd inserts list keys into
 * the path ahead of nodes that in YANG are siblings of the list key), and
 * the configd path cannot contain multiple elements at the same level (unlike
 * the subtree filter), and also as we do full filtering on the returned data
 * anyway, the algorithm is to walk the subtree filter path only as far as the
 * first YANG 'list' node (using TmplGet() to determine this).
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <vyatta-cfg/client/mgmt.h>
#include <vyatta-util/map.h>

#include "configd_path.h"

#define MAX_PATH_LEN 1024

/*
 * multiple_elements_exist
 * Returns 1 if the given node and siblings contain more than one element
 * node (don't count 'text' type etc).  If 0 or 1, returns 0 (false).
 */
static int multiple_elements_exist(xmlNode *node)
{
	xmlNode *cur_node = NULL;
	int count = 0;

	for (cur_node = node; cur_node; cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE) {
			count++;
		}
	}

	return (count > 1) ? 1 : 0;
}

/*
 * get_first_element
 *
 * Returns first node of type XML_ELEMENT_NODE from <node> and siblings.
*/
xmlNode *get_first_element(xmlNode *node)
{
	while (node != NULL) {
		if (node->type == XML_ELEMENT_NODE) {
			return node;
		}
		node = node->next;
	}
	return node;
}

/*
 * configd_strdup() - so we can track memory leaks with CppUTest, we can't
 * use strdup() as CppUTest can't track that.  Instead, write our own version
 * that uses (tracked) malloc.
 */
char *configd_strdup(char *src)
{
	int len = strlen(src);
	char *ret_str = malloc(len + 1);
	if (ret_str == NULL) {
		return NULL;
	}

	bzero(ret_str, len + 1);
	strcpy(ret_str, src);

	return ret_str;
}

/*
 * get_filter_element
 *
 * Returns filter node if:
 *   - there is exactly one 'filter' element
 *   - this element either has no type, or explicit type is 'subtree'
 * Otherwise returns NULL
 */
static xmlNode *get_filter_element(xmlNode *node)
{
	xmlChar *type_string = NULL;
	xmlNode *elem = NULL;
	xmlNode *filter_elem = NULL;

	// Do we have a 'filter' element? (good)
	elem = get_first_element(node);
	while (elem && strcmp("filter", (char *)elem->name)) {
		elem = get_first_element(elem->next);
	}
	if (elem == NULL) {
		return NULL;
	}
	filter_elem = elem;

	// Do we have a second 'filter' element (bad)
	elem = get_first_element(elem->next);
	while (elem) {
		if (!strcmp("filter", (char *)elem->name)) {
			return NULL;
		}
		elem = get_first_element(elem->next);
	}

	// If filter type is specified, it must be 'subtree'.
	type_string = xmlGetProp(filter_elem, (const unsigned char *)"type");
	if ((type_string != NULL) && strcmp("subtree", (const char *)type_string)) {
		xmlFree(type_string);
		return NULL;
	}
	xmlFree(type_string);

	return filter_elem;
}

/*
 * string_only_contains_whitespace
 *
 * Return 1 (true) if string only contains space, TAB, newline or carriage
 * return.
 */
static int string_only_contains_whitespace(unsigned char *str)
{
	unsigned char *cp;

	for (cp = str; *cp; cp++) {
		if ((*cp != ' ') && (*cp != '\t') && (*cp != '\n') && (*cp != '\r')) {
			return 0;
		}
	}
	return 1;
}

// Content-match node has single text child.
static int is_content_match_node(xmlNode *node)
{
	xmlNode *cm_child = NULL;

	// Must be valid node, with a 'text' type child node.
	if ((node == NULL) || (node->children == NULL)) {
		return 0;
	}

	cm_child = node->children;

	// Multiple children, so not content match.
	if (cm_child->next != NULL) {
		return 0;
	}

	if (cm_child->type != XML_TEXT_NODE) {
		return 0;
	}

	if (string_only_contains_whitespace(cm_child->content)) {
		return 0;
	}

	return 1;
}

// A YANG 'list' node is the only node type that has a 'tag' attribute in the
// map returned by TmplGet().
static int is_list_node(char *path, struct configd_ds *ds)
{
	struct configd_error *error = NULL;
	struct map *tmpl_map;

	tmpl_map = configd_tmpl_get(&ds->conn, path, error);

	const char *tag = map_get(tmpl_map, "tag");
	int is_tag = tag && (strcmp(tag, "1") == 0);

	// Can't call this until *after* all use of 'tag' is done.
	map_free(tmpl_map);

	return is_tag;
}

/*
 * get_config_path()
 *
 * Walks path in the filter as far as:
 *
 * - the first YANG 'list' node
 * - the node before multiple elements are specified at the same path depth
 * - the end of the path.
 *
 * This path thus determined is guaranteed to return enough information so
 * that when we apply the full subtree filter on the returned data, nothing
 * will have been missed out.
 *
 * Note that in some cases, eg when path ends with the list key, it would be
 * marginally faster to pass configd the key.  However, there are other cases
 * where we may have a non-key leaf specified, and in this case we have to
 * truncate the path as we don't know what key to use (and configd path will
 * not work without this inserted).
 */
static char *get_config_path(xmlNode *root, struct configd_ds *ds)
{
	char *path = NULL;
	xmlNode *node = NULL;
	int bytes_used = 0;
	char *name = NULL;

	node = get_first_element(root);
	if (node == NULL) {
		return configd_strdup(NO_PATH);
	}

	path = malloc(MAX_PATH_LEN + 1);
	bzero(path, MAX_PATH_LEN + 1);

	// As soon as we have multiple elements, we return path to parent node.
	while (node && !multiple_elements_exist(node)) {
		name = (char *)node->name;

		// If this will overrun the buffer, just go with what we have so far.
		if ((bytes_used + sizeof(name) + 1 /* for '/' */) >= MAX_PATH_LEN) {
			return path;
		}

		// If content-match node, return without adding node name to path.
		if (is_content_match_node(node)) {
			return path;
		}

		// Add to path, update root, and loop.
		strncat(path, "/", MAX_PATH_LEN - bytes_used);
		bytes_used += 1;
		strncat(path, name, MAX_PATH_LEN - bytes_used);
		bytes_used += sizeof(name);

		/*
		 * If list node, return at this point.  See function comment for
		 * more explanation.
		 */
		if (is_list_node(path, ds)) {
			return path;
		}

		node = get_first_element(node->children);
	}
	return path;
}

/*
 * configd_convert_filter_to_config_path
 *
 * Attempt to extract a 'configd' path from the subtree filter, if present.
 * If we can't extract anything, we return the 'root' path, which means we
 * will ask configd to return everything, and filter afterwards.
 */
char *configd_convert_filter_to_config_path(
	const nc_rpc *rpc, struct configd_ds *ds)
{
    xmlNode *root = NULL, *filter_node = NULL;
	xmlDoc *doc = NULL;
	char *path = NULL;

    /*
     * Apparently required to initialise the library and check the version
	 * is as expected.
     */
    LIBXML_TEST_VERSION;

	unsigned char *op_content = (unsigned char *)nc_rpc_get_op_content(rpc);
	if (rpc == NULL) {
		return configd_strdup(NO_PATH);
	}
	doc = xmlParseDoc(op_content);
    if (doc == NULL) {
		return configd_strdup(NO_PATH);
    }

    /*Get the root element node */
    root = xmlDocGetRootElement(doc);

	// Looking for <get / get-config> / <filter type="subtree">
	if (strcmp("get", (char *)root->name) &&
		strcmp("get-config", (char *)root->name)) {
		xmlFreeDoc(doc);
		xmlCleanupParser();
		return configd_strdup(ROOT_PATH);
	}

	// No filter means we should return ALL data.
	filter_node = get_filter_element(root->children);
	if (filter_node == NULL) {
		xmlFreeDoc(doc);
		xmlCleanupParser();
		return configd_strdup(ROOT_PATH);
	}

	path = get_config_path(filter_node->children, ds);

    /*free the document */
    xmlFreeDoc(doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

	return path;
}
