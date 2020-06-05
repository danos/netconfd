/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
 *
 * Copyright (c) 2014-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <libgen.h>
#include <syslog.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <vyatta-cfg/client/mgmt.h>
#include <vyatta-util/map.h>

#include "configd_datastore.h"
#include "configd_path.h"
#include "configd_xml_utils.h"

#define LOG(format,args...) syslog(LOG_ERR, format, ##args)

#define FILE_PERM 0660
#define DIR_PERM 0770
#define MASK_PERM 0006
#define XMLREAD_OPTIONS XML_PARSE_NOBLANKS|XML_PARSE_NSCLEAN|XML_PARSE_NOERROR|XML_PARSE_NOWARNING
#define NC_NS_BASE10 "urn:ietf:params:xml:ns:netconf:base:1.0"
#define NC_NS_BASE10_ID "base10"
#define NC_NS_MONITORING_ID "monitor"
#define NC_NS_MONITORING "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"


enum {
	GET_CONFIG = 0,
	GET_FULL
};

static void set_nc_err_field_from_mgmt_err(
	struct nc_err *err,
	NC_ERR_PARAM param,
	const char *value)
{
	if (value != NULL) {
		nc_err_set(err, param, value);
	}
}

// map_next returns a string of the form 'key=value'.  This function returns
// !0 if the key part of key_eq_value_str matches the key_name, otherwise 0.
static int key_equals(const char *key_name, const char *key_eq_value_str)
{
	return (!strncmp(key_name, key_eq_value_str, strlen(key_name)));
}

static void set_nc_err_info_fields_from_mgmt_error(
	struct nc_err *err,
	struct map *mgmt_info)
{
	const char *key_eq_value_str = NULL;

	if (mgmt_info == NULL) {
		return;
	}

	while ((key_eq_value_str = map_next(mgmt_info, key_eq_value_str))) {
		if (key_equals("bad-element", key_eq_value_str)) {
			nc_err_set(err, NC_ERR_PARAM_INFO_BADELEM,
				map_get(mgmt_info, "bad-element"));
		} else if (key_equals("bad-attribute", key_eq_value_str)) {
			nc_err_set(err, NC_ERR_PARAM_INFO_BADATTR,
				map_get(mgmt_info, "bad-attribute"));
		} else if (key_equals("bad-namespace", key_eq_value_str)) {
			nc_err_set(err, NC_ERR_PARAM_INFO_BADNS,
				map_get(mgmt_info, "bad-namespace"));
		} else if (key_equals("session-id", key_eq_value_str)) {
			nc_err_set(err, NC_ERR_PARAM_INFO_SID,
				map_get(mgmt_info, "session-id"));
		} else {
			LOG("E| %s unrecognised info: %s (%s:%d)",
				__func__, key_eq_value_str, __FILE__, __LINE__);
		}
	}
}

struct nc_err *nc_err_from_cfg_mgmt_err(struct configd_mgmt_error *me)
{
	struct nc_err *err;

	// By using NC_ERR_EMPTY, *no* fields are prepopulated.
	err = nc_err_new(NC_ERR_EMPTY);
	if (err == NULL) {
		return NULL;
	}

	set_nc_err_field_from_mgmt_err(err,
		NC_ERR_PARAM_TYPE, configd_mgmt_error_type(me));
	set_nc_err_field_from_mgmt_err(err,
		NC_ERR_PARAM_SEVERITY, configd_mgmt_error_severity(me));
	set_nc_err_field_from_mgmt_err(err,
		NC_ERR_PARAM_TAG, configd_mgmt_error_tag(me));
	set_nc_err_field_from_mgmt_err(err,
		NC_ERR_PARAM_MSG, configd_mgmt_error_message(me));
	set_nc_err_field_from_mgmt_err(err,
		NC_ERR_PARAM_PATH, configd_mgmt_error_path(me));
	set_nc_err_field_from_mgmt_err(err,
		NC_ERR_PARAM_APPTAG, configd_mgmt_error_app_tag(me));

	set_nc_err_info_fields_from_mgmt_error(
		err, (struct map *)configd_mgmt_error_info(me));

	return err;

}

nc_reply *configd_ds_basic_nc_error(
	NC_ERR err_type,
	const char* err_text,
	const char *fallback_text)
{
	struct nc_err *ne;

	ne = nc_err_new(err_type);
	if (err_text != NULL) {
		nc_err_set(ne, NC_ERR_PARAM_MSG, err_text);
	} else if (fallback_text != NULL) {
		nc_err_set(ne, NC_ERR_PARAM_MSG, fallback_text);
	} else {
		nc_err_set(ne, NC_ERR_PARAM_MSG, "Unspecified config system error");
	}

	return nc_reply_error(ne);
}

nc_reply *configd_ds_build_reply_error(
	struct configd_error *ce,
	NC_ERR err_type,
	const char *fallback_text)
{
	int num_errors = configd_error_num_mgmt_errors(ce);
	nc_reply *rep = NULL;
	struct nc_err *ne;
	int i = 0;

	if ((num_errors == 0) || !configd_error_is_mgmt_error(ce)) {
		return configd_ds_basic_nc_error(
			err_type, ce->text, fallback_text);
	}

	struct configd_mgmt_error **mgmt_err_list =
		configd_error_mgmt_error_list(ce);
	if ((mgmt_err_list == NULL) || (mgmt_err_list[0] == NULL)) {
		return configd_ds_basic_nc_error(err_type, ce->text, fallback_text);
	}

	ne = nc_err_from_cfg_mgmt_err(mgmt_err_list[0]);
	rep = nc_reply_error(ne);

	for (i = 1; i < num_errors; i++) {
		nc_reply_error_add(
			rep, nc_err_from_cfg_mgmt_err(mgmt_err_list[i]));
	}

	return rep;
}
struct configd_ds *new_configd_ds() {
	return calloc(1, sizeof(struct configd_ds));
}

int configd_ds_init(void *ds)
{
	int rc;

	struct configd_ds *configd_ds = (struct configd_ds*)ds;

	struct configd_conn *conn = &configd_ds->conn;
	rc = configd_open_connection(conn);
	if (rc != 0) {
		LOG("E| %s", "Failed to open configd connection");
		return EXIT_FAILURE;
	}

	/* Start shared netconf session */
	/* need a unique id for the session id, use an encoding of netconf for now */
	configd_set_session_id(conn, "NETCONF");

	if (configd_sess_exists(conn, NULL) != 1) {
		struct configd_error err = { .source = NULL, .text = NULL };
		rc = configd_sess_setup(conn, &err);
		if (rc < 0) {
			if (err.text != NULL) {
				LOG("E| %s %s", "Failed to setup configd session", err.text);
			} else {
				LOG("E| %s", "Failed to setup configd session");
			}
			configd_error_free(&err);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

void configd_ds_free(void *ds)
{
	struct configd_ds *configd_ds = (struct configd_ds*)ds;

	if (configd_ds == NULL) {
		return;
	}

	/* close configd connection */
	configd_close_connection(&configd_ds->conn);
}

static int configd_ds_changed(void *ds)
{
	struct configd_ds *configd_ds = (struct configd_ds*)ds;
	if (configd_sess_exists(&configd_ds->conn, NULL) == 1) {
		if (configd_sess_changed(&configd_ds->conn, NULL) == 1) {
			return EXIT_SUCCESS;
		}
	}
	return EXIT_FAILURE;
}

static char *configd_filter(xmlNodePtr tree, const nc_rpc *rpc, struct nc_err **error)
{
	xmlNodePtr aux_node = NULL, node = NULL;
	xmlBufferPtr resultbuffer = NULL;
	int ret = EXIT_FAILURE;
	char *out = NULL;

	struct nc_filter *filter = nc_rpc_get_filter(rpc);

	resultbuffer = xmlBufferCreate();
	if (resultbuffer == NULL) {
		LOG("E| %s", "failed to setup resultbuffer");
		return NULL;
	}

	/* Format for netconf (strip root) */
	for (aux_node = tree->children; aux_node != NULL; aux_node = aux_node->next) {
		if (filter != NULL) {
			/* Get disconnected subtree to filter against */
			xmlNodePtr subtree = xmlCopyNode(aux_node, 1);
			ret = ncxml_filter(subtree, filter, &node, NULL);
			xmlFreeNode(subtree);
			if (ret != EXIT_SUCCESS) {
				*error = nc_err_new(NC_ERR_BAD_ELEM);
				nc_err_set(*error, NC_ERR_PARAM_TYPE, "protocol");
				nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "filter");
				break;
			}
		} else {
			node = xmlCopyNode(aux_node, 1);
		}

		if (node != NULL) {
			xmlNodeDump(resultbuffer, NULL, node, 2, 1);
			xmlFreeNode(node);
			node = NULL;
		}
	}

	/* get the buffer out of libxml2 land */
	out = strdup((const char *) xmlBufferContent(resultbuffer));

	xmlBufferFree(resultbuffer);
	return out;
}

static char* configd_get_rpc_config(const nc_rpc* rpc, struct nc_err **error)
{
	char *config, *data;
	xmlDocPtr doc1;
	config = nc_rpc_get_config(rpc);
	if (config == NULL) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		return NULL;
	}
	if (strcmp(config, "") == 0) {
		return config;
	}
	/*
	 * config can contain multiple elements on the root level, so
	 * cover it with the <config> element to allow the creation of
	 * xml document
	 */
	if (asprintf(&data, "<config>%s</config>", config) == -1) {
		syslog(LOG_ERR, "asprintf() failed (%s:%d).", __FILE__, __LINE__);
		*error = nc_err_new(NC_ERR_OP_FAILED);
		return NULL;
	}
	free(config);
	config = NULL;
	doc1 = xmlReadDoc(BAD_CAST data, NULL, NULL, XMLREAD_OPTIONS);
	if (doc1 == NULL || doc1->children == NULL || doc1->children->children == NULL) {
		if (doc1 != NULL) {
			xmlFreeDoc(doc1);
		}
		*error = nc_err_new(NC_ERR_INVALID_VALUE);
		nc_err_set(*error, NC_ERR_PARAM_MSG, "Invalid <config> parameter of the rpc request.");
		return NULL;
	}

	if (doc1 != NULL) {
		xmlFreeDoc(doc1);
	}

	return data;
}

static nc_reply * configd_ds_get_internal(
	struct configd_ds *configd_ds,
	const nc_rpc *rpc,
	NC_DATASTORE source,
	int get_op,
	struct nc_err** error)
{
	Db target_ds;
	char *tree = NULL;
	xmlNode *data = NULL;
	xmlDocPtr doc;
	char *path = NULL;
	nc_reply *reply = NULL;
	int flags = CONFIGD_TREEGET_SECRETS;

	/* check validity of function parameters */
	switch(source) {
	case NC_DATASTORE_RUNNING:
		target_ds = RUNNING;
		break;
		/*case NC_DATASTORE_STARTUP:
			// TODO(jhs): need to be able to convert vyatta config files to xml
			break;*/
	case NC_DATASTORE_CANDIDATE:
		target_ds = CANDIDATE;
		break;
	default:
		LOG("%s: invalid target.", __func__);
		*error = nc_err_new(NC_ERR_BAD_ELEM);
		nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "source");
		return NULL;
		break;
	}

	NCWD_MODE mode = ncdflt_rpc_get_withdefaults(rpc);
	switch (mode) {
	case NCWD_MODE_ALL:
		flags |= CONFIGD_TREEGET_DEFAULTS;
		break;
	case NCWD_MODE_NOTSET:
	case NCWD_MODE_EXPLICIT:
		/* no defaults in output */
		break;
	case NCWD_MODE_TRIM:
	case NCWD_MODE_ALL_TAGGED:
	default:
		LOG("E| %s: invalid default retrieval mode.", __func__);
		*error = nc_err_new(NC_ERR_BAD_ATTR);
		nc_err_set(*error, NC_ERR_PARAM_INFO_BADATTR, "with-defaults");
		return NULL;
		break;
	}

	/*
	 * We can significantly speed up operations by extracting the basic
	 * 'configd' YANG path from the requested filter and passing that into
	 * configd.  We still need to filter the returned result as configd
	 * just takes a basic 'path/to/node' path which doesn't allow for
	 * content-match, multiple nodes requested at the same level etc.
	 */
	path = configd_convert_filter_to_config_path(rpc, configd_ds);
	if (path == NULL) {
		return NULL;
	}
	/*
	 * If we failed to extract a path, this could be for many different
	 * reasons.  To be on the safe side, given path extraction here is
	 * an optimisation, we will let configd return ALL data and filter the
	 * response from configd later rather than assume an error here.
	 */
	if (!strcmp(path, NO_PATH)) {
		path[0] = '\0';
	}

	struct configd_error err = { .source = NULL, .text = NULL };
	switch (get_op) {
		case GET_CONFIG:
			tree = configd_tree_get_encoding_flags(&configd_ds->conn,
							target_ds, path, "netconf", flags, &err);
		break;
		case GET_FULL:
			tree = configd_tree_get_full_encoding_flags(&configd_ds->conn,
							target_ds, path, "netconf", flags, &err);
		break;
	}
	free(path);

	if (tree == NULL || err.text != NULL) {
		LOG("E| %s accessing ds failed: %s (%s:%d)", __func__, err.text,  __FILE__, __LINE__);
		reply = configd_ds_build_reply_error(
			&err, NC_ERR_OP_FAILED,
			"GET / GET-CONFIG operation failed.");
		goto done;
	}

	/* read config to XML doc */
	if ((doc = xmlReadMemory (tree, strlen(tree), NULL, NULL, XMLREAD_OPTIONS)) == NULL) {
		LOG("E| %s xmlReadMemory failed", __func__);
		reply = NULL;
		goto done;
	}
	free(tree);

	data = doc->children;

	char *output = configd_filter(data, rpc, error);

	if (output == NULL) {
		reply = NULL;
	} else {
		reply = nc_reply_data(output);
	}
	free(output);
	xmlFreeDoc(doc);
done:
	configd_error_free(&err);
	return reply;
}

static nc_reply * configd_ds_getconfig(struct configd_ds *configd_ds, const nc_rpc *rpc, NC_DATASTORE source, struct nc_err** error)
{
	return configd_ds_get_internal(configd_ds, rpc, source, GET_CONFIG, error);
}

nc_reply * configd_ds_get_all(struct configd_ds *configd_ds, const nc_rpc *rpc, NC_DATASTORE source, struct nc_err** error)
{
	return configd_ds_get_internal(configd_ds, rpc, source, GET_FULL, error);
}

static int discard_config(struct configd_conn *conn)
{
	/* Discard candidate */
	struct configd_error err = { .source = NULL, .text = NULL };

	/* Discard only fails if no changes exist netconf does not consider this to be an error*/
	char *buf = configd_discard(conn, &err);
	if (buf == NULL) {
		if (err.text) {
			LOG("E| %s", err.text);
		} else {
			LOG("E| Failed to discard candidate");
		}
	}
	free(buf);
	configd_error_free(&err);
	return EXIT_SUCCESS;
}

static int is_sess_locked(struct configd_ds *ds, struct nc_err **error)
{
	int lockid = configd_sess_locked(&ds->conn, NULL);
	if ((lockid != 0) && (lockid != ds->lockid)) {
		char *idstr;
		*error = nc_err_new (NC_ERR_LOCK_DENIED);
		if (asprintf(&idstr, "%d", lockid) != -1)
			nc_err_set(*error, NC_ERR_PARAM_INFO_SID, idstr);
		return 1;
	}
	return 0;
}

static nc_reply *configd_ds_editconfig(struct configd_ds *configd_ds, const nc_rpc *rpc, NC_EDIT_DEFOP_TYPE defop, NC_EDIT_ERROPT_TYPE errop, struct nc_err **error)
{
	xmlDocPtr config_doc;
	nc_reply *rep = NULL;
	char *config = NULL;

	config = configd_get_rpc_config(rpc, error);
	if (config == NULL) {
		return rep;
	}

	NC_DATASTORE target = nc_rpc_get_target(rpc);
	switch(target) {
	case NC_DATASTORE_CANDIDATE:
		if (is_sess_locked(configd_ds, error))
			goto out;
		break;
	default:
		LOG("%s: invalid target.", __func__);
		/* fallthrough */
	case NC_DATASTORE_ERROR:
		*error = nc_err_new(NC_ERR_BAD_ELEM);
		nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "target");
		goto out;
	}

	const char *defaultop;
	switch (defop) {
	case NC_EDIT_DEFOP_NOTSET:
	case NC_EDIT_DEFOP_MERGE:
		defaultop = "merge";
		break;
	case NC_EDIT_DEFOP_REPLACE:
		defaultop = "replace";
		break;
	case NC_EDIT_DEFOP_NONE:
		defaultop = "none";
		break;
	default:
		*error = nc_err_new(NC_ERR_BAD_ELEM);
		nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "default-operation");
		goto out;
	}

	/* get validation option */
	const char *testopt;
	NC_EDIT_TESTOPT_TYPE top = nc_rpc_get_testopt(rpc);
	switch (top) {
	case NC_EDIT_TESTOPT_NOTSET:
	case NC_EDIT_TESTOPT_TESTSET:
		testopt = "test-then-set";
		break;
	case NC_EDIT_TESTOPT_SET:
		testopt = "set";
		break;
	case NC_EDIT_TESTOPT_TEST:
		testopt = "test-only";
		break;
	default:
		LOG("%s: invalid testopt.", __func__);
		*error = nc_err_new(NC_ERR_BAD_ELEM);
		nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "test-option");
		goto out;
	}

	/* error option */
	const char *erropt;
	switch (errop) {
	case NC_EDIT_ERROPT_NOTSET:
	case NC_EDIT_ERROPT_STOP:
		erropt = "stop-on-error";
		break;
	case NC_EDIT_ERROPT_CONT:
		erropt = "continue-on-error";
		break;
	case NC_EDIT_ERROPT_ROLLBACK:
		erropt = "rollback-on-error";
		break;
	default:
		LOG("%s: invalid erropt.", __func__);
		*error = nc_err_new(NC_ERR_BAD_ELEM);
		nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "error-option");
		goto out;
	}

	/* read config to XML doc */
	if ((config_doc = xmlReadMemory (config, strlen(config), NULL, NULL, XMLREAD_OPTIONS)) == NULL) {
		goto out;
	}
	xmlChar *edit_config = NULL;
	xmlDocDumpMemory(config_doc, &edit_config, NULL);

	/* preform edit-config */
	struct configd_error err = { .source = NULL, .text = NULL };
	char *result = configd_edit_config_xml(&configd_ds->conn, "candidate", defaultop, testopt, erropt, (const char *)edit_config, &err);
	if (!result) {
		rep = configd_ds_build_reply_error(
			&err, NC_ERR_OP_FAILED,
			"edit-config operation failed");

	} else {
		 rep = nc_reply_ok();
	}
	configd_error_free(&err);
	xmlFree(edit_config);
	xmlFreeDoc (config_doc);

out:
	free(config);
	return rep;
}

static int configd_ds_cancelcommit(struct configd_ds *configd_ds, const nc_rpc *rpc, struct nc_err **error)
{
	int retval = EXIT_SUCCESS;
	char *buf = NULL;
	struct configd_error err = { .source = NULL, .text = NULL };
	struct configd_conn *conn = &configd_ds->conn;
	char *persistid = NULL;

	persistid = configd_get_rpc_value("cancel-commit", "persist-id", rpc);
	buf = configd_cancel_commit(conn, "via netconf", persistid, &err);
	if (buf == NULL) {
		*error = nc_err_new (NC_ERR_OP_FAILED);
		if (err.text != NULL) {
			nc_err_set(*error, NC_ERR_PARAM_MSG, err.text);
		} else {
			nc_err_set(*error, NC_ERR_PARAM_MSG, "Failed to cancel confirmed commit");
		}
		retval = EXIT_FAILURE;
	} else {
		free(buf);
	}

	if (persistid != NULL) {
		free(persistid);
	}

	return retval;
}

static nc_reply *commit_internal(struct configd_conn *conn, const nc_rpc *rpc)
{
	char *buf = NULL;
	char *persistid = NULL;
	char *persist = NULL;
	char *timeout = NULL;
	int confirmed = 0;
	nc_reply *rep = NULL;
	struct configd_error err = { .source = NULL, .text = NULL };

	persistid = configd_get_rpc_value("commit", "persist-id", rpc);
	persist = configd_get_rpc_value("commit", "persist", rpc);
	timeout = configd_get_rpc_value("commit", "confirm-timeout", rpc);
	confirmed = configd_rpc_value_exists("commit", "confirmed", rpc);

	buf = configd_confirmed_commit(conn, "via netconf",
			confirmed, timeout, persist, persistid, &err);

	if (buf == NULL) {
		rep = configd_ds_build_reply_error(
			&err, NC_ERR_OP_FAILED,
			"Failed to commit candidate configuration.");
		configd_error_free(&err);
	} else {
		free(buf);
	}
	if (timeout != NULL) {
		free(timeout);
	}
	if (persistid != NULL) {
		free(persistid);
	}
	if (persist != NULL) {
		free(persist);
	}

	if (rep != NULL) {
		return rep;
	}

	return nc_reply_ok();
}

static nc_reply *configd_ds_copyconfig(
	struct configd_ds *configd_ds,
	NC_DATASTORE target,
	NC_DATASTORE source,
	const nc_rpc *rpc)
{
	struct nc_err *nce = NULL;
	int retval = EXIT_SUCCESS;
	nc_reply *rep = NULL;
	char *buf = NULL;
	struct configd_error err = { .source = NULL, .text = NULL };
	struct configd_conn *conn = &configd_ds->conn;

	/*Validate source and target*/
	switch(target) {
	case NC_DATASTORE_CANDIDATE:
		if (is_sess_locked(configd_ds, &nce))
			return nc_reply_error(nce);
	case NC_DATASTORE_STARTUP:
	case NC_DATASTORE_RUNNING:
	case NC_DATASTORE_CONFIG:
		break;
	default:
		LOG("%s: invalid target.", __func__);
		nce = nc_err_new(NC_ERR_BAD_ELEM);
		nc_err_set(nce, NC_ERR_PARAM_INFO_BADELEM, "target");
		return nc_reply_error(nce);
	}

	switch(source) {
	case NC_DATASTORE_RUNNING:
	case NC_DATASTORE_STARTUP:
	case NC_DATASTORE_CANDIDATE:
	case NC_DATASTORE_CONFIG:
		/* validation will happen in editconfig function no need to do it here */
		break;
	default:
		LOG("%s: invalid source.", __func__);
		nce = nc_err_new(NC_ERR_BAD_ELEM);
		nc_err_set(nce, NC_ERR_PARAM_INFO_BADELEM, "source");
		return nc_reply_error(nce);
	}

	// tree_get will handle NACM for read operations.
	// Write code to verify set and delete actions before hand.

	switch (target) {
	case NC_DATASTORE_STARTUP:
		switch (source) {
		case NC_DATASTORE_RUNNING:
			/* save() */
			buf = configd_save(conn, "", &err);
			if (buf == NULL) {
				rep = configd_ds_build_reply_error(
					&err, NC_ERR_OP_FAILED,
					"Failed to save running to startup.");
			} else {
				rep = nc_reply_ok();
			}
			configd_error_free(&err);
			free(buf);
			return rep;
		case NC_DATASTORE_STARTUP:
			/* nop */
			break;
		case NC_DATASTORE_CONFIG:
			/* not allowed by our system */
		case NC_DATASTORE_CANDIDATE:
			/* not allowed by our system */
		default:
			LOG("%s: invalid target.", __func__);
			nce = nc_err_new(NC_ERR_BAD_ELEM);
			nc_err_set(nce, NC_ERR_PARAM_INFO_BADELEM, "source");
			return nc_reply_error(nce);
		}
		break;
	case NC_DATASTORE_CANDIDATE:
		switch (source) {
		case NC_DATASTORE_RUNNING:
			/* discard */
			retval = discard_config(conn);
			break;
		case NC_DATASTORE_STARTUP:
			/* load() */
			retval = discard_config(conn);
			if (retval == EXIT_FAILURE) {
				break;
			}
			if (configd_load(conn, "/config/config.boot", &err) != 1) {
				rep = configd_ds_build_reply_error(
					&err, NC_ERR_OP_FAILED,
					"Failed to copy startup to candidate.");
			} else {
				rep = nc_reply_ok();
			}
			configd_error_free(&err);
			return rep;
		case NC_DATASTORE_CANDIDATE:
			/* nop */
			break;
		case NC_DATASTORE_CONFIG:
			/* editconfig DEFOP = REPLACE */
			return nc_reply_error(nc_err_new(NC_ERR_OP_NOT_SUPPORTED));
		default:
			break;
		}
		break;
	case NC_DATASTORE_RUNNING:
		switch (source) {
		case NC_DATASTORE_RUNNING:
			/* nop */
			break;
		case NC_DATASTORE_CANDIDATE:
			/* commit */
			return commit_internal(conn, rpc);
		default:
			LOG("%s: invalid target.", __func__);
			nce = nc_err_new(NC_ERR_BAD_ELEM);
			nc_err_set(nce, NC_ERR_PARAM_INFO_BADELEM, "target");
			return nc_reply_error(nce);
		}
		break;
	case NC_DATASTORE_CONFIG:
		LOG("%s: invalid target.", __func__);
		nce = nc_err_new(NC_ERR_BAD_ELEM);
		nc_err_set(nce, NC_ERR_PARAM_INFO_BADELEM, "target");
		return nc_reply_error(nce);

	default:
		break;
	}

	if (retval == EXIT_SUCCESS) {
		return nc_reply_ok();
	}
	return nc_reply_error(nc_err_new(NC_ERR_OP_FAILED));
}


static int configd_ds_deleteconfig(struct configd_ds *configd_ds, NC_DATASTORE target, struct nc_err **error)
{
	int retval = EXIT_SUCCESS;

	switch(target) {
	case NC_DATASTORE_RUNNING:
		*error = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set (*error, NC_ERR_PARAM_MSG, "Cannot delete a running datastore.");
		retval = EXIT_FAILURE;
		break;
	case NC_DATASTORE_STARTUP:
		/* Copy config.boot.default to config.boot */
		break;
	case NC_DATASTORE_CANDIDATE:
		/* Discard candidate */
		retval = discard_config(&configd_ds->conn);
		break;
	default:
		LOG("%s: invalid target.", __func__);
		*error = nc_err_new(NC_ERR_BAD_ELEM);
		nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "target");
		retval = EXIT_FAILURE;
		break;
	}

	return retval;
}

static nc_reply* configd_ds_validate(struct configd_ds *ds, const nc_rpc * rpc)
{
	NC_DATASTORE source;
	struct nc_err *e = NULL;
	nc_reply *rep = NULL;
	char *buf = NULL;
	struct configd_error err = { .source = NULL, .text = NULL };

	struct configd_ds *configd_ds = (struct configd_ds*)ds;

	if (configd_ds_changed(ds) == EXIT_FAILURE) {
		rep = nc_reply_ok();
		return rep;
	}
	/*Vyatta can only validate the candidate configuration right now*/
	switch (source = nc_rpc_get_source(rpc)) {
	case NC_DATASTORE_CANDIDATE:
		buf = configd_validate(&configd_ds->conn, &err);
		if (buf == NULL) {
			rep = configd_ds_build_reply_error(
				&err, NC_ERR_OP_FAILED,
				"Validation failed for candidate configuration.");
		} else {
			rep = nc_reply_ok();
		}
		configd_error_free(&err);
		free(buf);
		break;
	default:
		/*The error is freed when reply is sent*/
		e = nc_err_new(NC_ERR_BAD_ELEM);
		nc_err_set(e, NC_ERR_PARAM_INFO_BADELEM, "source");
		rep = nc_reply_error(e);
		break;
	}

	return rep;
}

static int configd_ds_lock(struct configd_ds *ds, NC_DATASTORE target, struct nc_err **error)
{
	int lockid = 0;
	switch(target) {
	case NC_DATASTORE_CANDIDATE:
		break;
	case NC_DATASTORE_STARTUP:
	case NC_DATASTORE_RUNNING:
	case NC_DATASTORE_CONFIG:
	default:
		LOG("%s: invalid target.", __func__);
		*error = nc_err_new(NC_ERR_BAD_ELEM);
		nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "target");
		return EXIT_FAILURE;
	}

	if (configd_ds_changed(ds) == EXIT_SUCCESS) {
		*error = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set(*error, NC_ERR_PARAM_MSG, "Candidate configuration is changed");
		return EXIT_FAILURE;
	}
	struct configd_error err = { .source = NULL, .text = NULL };

	lockid = configd_sess_lock(&ds->conn, &err);
	if (lockid > 0) {
		ds->lockid = lockid;
		configd_error_free(&err);
		return EXIT_SUCCESS;
	}
	*error = nc_err_new (NC_ERR_LOCK_DENIED);
	if (err.text != NULL) {
		nc_err_set(*error, NC_ERR_PARAM_INFO_SID, err.text);
	}
	configd_error_free(&err);
	return EXIT_FAILURE;
}

static int configd_ds_unlock(struct configd_ds *ds, NC_DATASTORE target, struct nc_err **error)
{
	int lockid = 0;
	switch(target) {
	case NC_DATASTORE_CANDIDATE:
		break;
	case NC_DATASTORE_STARTUP:
	case NC_DATASTORE_RUNNING:
	case NC_DATASTORE_CONFIG:
	default:
		LOG("%s: invalid target.", __func__);
		*error = nc_err_new(NC_ERR_BAD_ELEM);
		nc_err_set(*error, NC_ERR_PARAM_INFO_BADELEM, "target");
		return EXIT_FAILURE;
	}

	// Discard candidate on unlock (RFC 6241 Section 8.3.5.2). We
	// don't care if this fails (e.g., somebody else holds the
	// lock) as the unlock operation will also fail informing the
	// client. However, if there is no lock, don't discard and let
	// unlock report that there was no lock.
	if (configd_sess_locked(&ds->conn, NULL) > 0) {
		configd_discard(&ds->conn, NULL);
	}

	struct configd_error err = { .source = NULL, .text = NULL };
	lockid = configd_sess_unlock(&ds->conn, &err);
	if ((lockid != 0) && (lockid == ds->lockid)) {
		ds->lockid = -1;
		configd_error_free(&err);
		return EXIT_SUCCESS;
	} else if (lockid == 0) {
		*error = nc_err_new (NC_ERR_OP_FAILED);
		nc_err_set(*error, NC_ERR_PARAM_MSG, "Session is not locked");
	} else if (err.text != NULL) {
		*error = nc_err_new (NC_ERR_LOCK_DENIED);
		nc_err_set(*error, NC_ERR_PARAM_INFO_SID, err.text);
	} else {
		*error = nc_err_new (NC_ERR_OP_FAILED);
	}
	configd_error_free(&err);
	return EXIT_FAILURE;
}

static nc_reply *configd_ds_getschema(struct configd_ds *ds, const nc_rpc* rpc)
{
	nc_reply *reply;
	struct nc_err *e;
	struct configd_error err = { .source = NULL, .text = NULL };
	char *data = NULL;
	char *name = NULL, *format = NULL;
	xmlXPathObjectPtr query_result = NULL;

	xmlBufferPtr resultbuffer = NULL;

	/*copied from libnetconf*/
	char *rpctxt = nc_rpc_dump(rpc);
	xmlDocPtr doc = xmlReadMemory(rpctxt, strlen(rpctxt), NULL, NULL, XMLREAD_OPTIONS);
	xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
	free(rpctxt);

        /* register base namespace for the rpc */
        xmlXPathRegisterNs(ctx, BAD_CAST NC_NS_BASE10_ID, BAD_CAST NC_NS_BASE10);
        xmlXPathRegisterNs(ctx, BAD_CAST NC_NS_MONITORING_ID, BAD_CAST NC_NS_MONITORING);

	if ((query_result = xmlXPathEvalExpression(BAD_CAST
	     "/"NC_NS_BASE10_ID":rpc/"NC_NS_MONITORING_ID":get-schema/"NC_NS_MONITORING_ID":identifier",
	     ctx)) != NULL && !xmlXPathNodeSetIsEmpty(query_result->nodesetval)) {
		if (query_result->nodesetval->nodeNr > 1) {
			e = nc_err_new(NC_ERR_BAD_ELEM);
			nc_err_set(e, NC_ERR_PARAM_INFO_BADELEM, "identifier");
			nc_err_set(e, NC_ERR_PARAM_MSG, "Multiple \'identifier\' elements found.");
			xmlXPathFreeObject(query_result);
			xmlXPathFreeContext(ctx);
			xmlFreeDoc(doc);
			reply = nc_reply_error(e);
			return reply;
		}
		name = (char*) xmlNodeGetContent(query_result->nodesetval->nodeTab[0]);
		xmlXPathFreeObject(query_result);
	} else {
		if (query_result != NULL) {
			xmlXPathFreeObject(query_result);
		}
		e = nc_err_new(NC_ERR_INVALID_VALUE);
		nc_err_set(e, NC_ERR_PARAM_INFO_BADELEM, "identifier");
		nc_err_set(e, NC_ERR_PARAM_MSG, "Missing mandatory \'identifier\' element.");
		xmlXPathFreeContext(ctx);
		xmlFreeDoc(doc);
		reply = nc_reply_error(e);
		return reply;
	}

	/* get format of the schema */
	if ((query_result = xmlXPathEvalExpression(BAD_CAST
	     "/"NC_NS_BASE10_ID":rpc/"NC_NS_MONITORING_ID":get-schema/"NC_NS_MONITORING_ID":format",
	     ctx)) != NULL) {
		if (!xmlXPathNodeSetIsEmpty(query_result->nodesetval)) {
			if (query_result->nodesetval->nodeNr > 1) {
				e = nc_err_new(NC_ERR_BAD_ELEM);
				nc_err_set(e, NC_ERR_PARAM_INFO_BADELEM, "version");
				nc_err_set(e, NC_ERR_PARAM_MSG, "Multiple \'version\' elements found.");
				xmlXPathFreeObject(query_result);
				xmlXPathFreeContext(ctx);
				xmlFreeDoc(doc);
				reply = nc_reply_error(e);
				return reply;
			}
			format = (char*) xmlNodeGetContent(query_result->nodesetval->nodeTab[0]);
		}
		xmlXPathFreeObject(query_result);
	}
	xmlXPathFreeContext(ctx);
	xmlFreeDoc(doc);

	if (format == NULL) {
		/* format is missing, use yang as default format */
		format = strdup("yang");
	}


	if ((data = configd_schema_get(&ds->conn, name, format, &err)) == NULL) {
		e = nc_err_new(NC_ERR_INVALID_VALUE);
		nc_err_set(e, NC_ERR_PARAM_TYPE, "protocol");
		nc_err_set(e, NC_ERR_PARAM_MSG, "The requested schema does not exist.");
		reply = nc_reply_error(e);
		configd_error_free(&err);
		return reply;
	}
	if (strcmp(format, "yin") == 0) {
		doc = xmlReadMemory(data, strlen(data), NULL, NULL, XMLREAD_OPTIONS);
		resultbuffer = xmlBufferCreate();
		xmlNodeDump(resultbuffer, doc, doc->children, 2, 1);
		free(data);
		data = strdup((char *)xmlBufferContent(resultbuffer));
		xmlBufferFree(resultbuffer);
		xmlFreeDoc(doc);
	}

	reply = nc_reply_data_ns(data, "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring");
	free(data);
	return reply;
}

nc_reply* configd_ds_get(struct configd_ds *ds, const nc_rpc* rpc)
{
	xmlDocPtr doc1 = NULL, doc2 = NULL;
	xmlNodePtr aux_node = NULL, node = NULL;
	char *out = NULL;
	nc_reply *reply = NULL;
	char *data = NULL, *config = NULL, *netconf_state = NULL;
	struct nc_err *error = NULL;

	data = configd_get_schemas(&ds->conn, NULL);

	if (asprintf(&netconf_state,
		     "<netconf-state "
		     "xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\">"
		     "%s</netconf-state>",
		     (data == NULL) ? "" : data) == -1) {
		error = nc_err_new(NC_ERR_OP_FAILED);
		return nc_reply_error(error);
	}

	if ((doc1 = xmlReadMemory (netconf_state, strlen(netconf_state), NULL, NULL, XMLREAD_OPTIONS)) == NULL) {
		error = nc_err_new(NC_ERR_OP_FAILED);
		nc_reply_free(reply);
		return nc_reply_error(error);
	}
	free(data);
	free(netconf_state);

	reply = configd_ds_get_all(ds, rpc, NC_DATASTORE_RUNNING, &error);
	switch (nc_reply_get_type(reply)) {
	case NC_REPLY_DATA:
		break;
	case NC_REPLY_ERROR:
		return reply;
	default:
		return nc_reply_error(error);
	}

	config = nc_reply_get_data(reply);
	if (asprintf(&data, "<config>%s</config>", config) == -1) {
		syslog(LOG_ERR, "asprintf() failed (%s:%d).", __FILE__, __LINE__);
		error = nc_err_new(NC_ERR_OP_FAILED);
		nc_reply_free(reply);
		return nc_reply_error(error);
	}
	free(config);

	if ((doc2 = xmlReadMemory (data, strlen(data), NULL, NULL, XMLREAD_OPTIONS)) == NULL) {
		error = nc_err_new(NC_ERR_OP_FAILED);
		nc_reply_free(reply);
		return nc_reply_error(error);
	}
	nc_reply_free(reply);
	free(data);

	xmlNodePtr tree = xmlNewNode(NULL, BAD_CAST"tree");

	for (aux_node = doc2->children->children; aux_node != NULL; aux_node = aux_node->next) {
		node = xmlCopyNode(aux_node, 1);
		if (node != NULL) {
			xmlAddChild(tree, node);
			node = NULL;
		}
	}

	for (aux_node = doc1->children; aux_node != NULL; aux_node = aux_node->next) {
		node = xmlCopyNode(aux_node, 1);
		if (node != NULL) {
			xmlAddChild(tree, node);
			node = NULL;
		}
	}

	xmlFreeDoc(doc1);
	xmlFreeDoc(doc2);

	out = configd_filter(tree, rpc, &error);
	xmlFreeNode(tree);

	reply = nc_reply_data(out);
	free(out);

	return reply;
}

nc_reply* configd_ds_apply_rpc(struct configd_ds *ds, const nc_rpc* rpc)
{
	NC_OP op = NC_OP_UNKNOWN;
	struct nc_err* e = NULL;
	int ret = EXIT_FAILURE;
	nc_reply *rep = NULL;
	NC_DATASTORE target, source;

	op = nc_rpc_get_op(rpc);
	switch (op) {
	case NC_OP_LOCK:
		ret = configd_ds_lock(ds, nc_rpc_get_target(rpc), &e);
		break;
	case NC_OP_UNLOCK:
		ret = configd_ds_unlock(ds, nc_rpc_get_target(rpc), &e);
		break;
	case NC_OP_GET:
		/*
		 * Eventually we'll want to do the session state juggling that libnetconf does.
		 */
		rep = configd_ds_get_all(ds, rpc, NC_DATASTORE_RUNNING, &e);
		break;
	case NC_OP_GETCONFIG:
		rep = configd_ds_getconfig(ds, rpc, nc_rpc_get_source(rpc), &e);
		break;
	case NC_OP_EDITCONFIG:
		rep = configd_ds_editconfig(ds, rpc, nc_rpc_get_defop(rpc), nc_rpc_get_erropt(rpc), &e);
		break;
	case NC_OP_COPYCONFIG:
		if ((target = nc_rpc_get_target(rpc)) == NC_DATASTORE_ERROR) {
			e = nc_err_new(NC_ERR_BAD_ELEM);
			nc_err_set(e, NC_ERR_PARAM_INFO_BADELEM, "target");
			break;
		}
		if ((source = nc_rpc_get_source(rpc)) == NC_DATASTORE_ERROR) {
			e = nc_err_new(NC_ERR_BAD_ELEM);
			nc_err_set(e, NC_ERR_PARAM_INFO_BADELEM, "target");
			break;
		}
		rep = configd_ds_copyconfig(ds, target, source, NULL);
		break;
	case NC_OP_DELETECONFIG:
		ret = configd_ds_deleteconfig(ds, nc_rpc_get_target(rpc), &e);
		break;
	case NC_OP_COMMIT:
		rep = configd_ds_copyconfig (ds, NC_DATASTORE_RUNNING, NC_DATASTORE_CANDIDATE, rpc);
		break;
	case NC_OP_CANCELCOMMIT:
		ret = configd_ds_cancelcommit (ds, rpc, &e);
		break;
	case NC_OP_DISCARDCHANGES:
		rep = configd_ds_copyconfig(ds, NC_DATASTORE_CANDIDATE, NC_DATASTORE_RUNNING, NULL);
		break;
	case NC_OP_GETSCHEMA:
		rep = configd_ds_getschema(ds, rpc);
		break;
	case NC_OP_VALIDATE:
		rep = configd_ds_validate(ds, rpc);
		break;
	case NC_OP_UNKNOWN:
		rep = NCDS_RPC_NOT_APPLICABLE;
		break;
	default:
		break;
	}

	if (rep != NULL) {
		return rep;
	}

	/* build an error reply */
	if (e != NULL) {
		return nc_reply_error(e);
	}

	if (ret == EXIT_SUCCESS) {
		return nc_reply_ok();
	}

	return nc_reply_error(nc_err_new(NC_ERR_OP_FAILED));
}


nc_reply *configd_run_op_rpc(struct configd_ds *ds, const nc_rpc* rpc)
{
	nc_reply *rep;
	struct configd_error err = { .source = NULL, .text = NULL };
	char *namespace = nc_rpc_get_op_namespace(rpc);
	char *name = nc_rpc_get_op_name(rpc);
	char *body = nc_rpc_get_op_content(rpc);
	char *result = configd_call_rpc_xml(&ds->conn, namespace, name, body, &err);

	if (result) {
		xmlDoc *doc = NULL;
		xmlNode *root_element = NULL;

		doc = xmlReadMemory(result, strlen(result), NULL, NULL, XMLREAD_OPTIONS);
		if (!doc) {
			rep = nc_reply_error(nc_err_new(NC_ERR_OP_FAILED));
			goto done;
		}
		root_element = xmlDocGetRootElement(doc);
		if (!root_element) {
			rep = nc_reply_error(nc_err_new(NC_ERR_OP_FAILED));
			goto done_result;
		}
		if (xmlChildElementCount(root_element) == 0UL) {
			rep = nc_reply_ok();
			goto done_result;
		}

		xmlChar *reply = NULL;
		const nc_msgid msgid = nc_rpc_get_msgid(rpc);
		xmlSetProp(root_element, BAD_CAST "xmlns", BAD_CAST NC_NS_BASE10);
		xmlSetProp(root_element, BAD_CAST "message-id", BAD_CAST msgid);
		xmlDocDumpMemory(doc, &reply, NULL);
		rep = nc_reply_build((const char *)reply);
		xmlFree(reply);
done_result:
		xmlFreeDoc(doc);
	} else {
		struct nc_err *error = nc_err_new(NC_ERR_OP_FAILED);
		if (err.text && err.text[0]) {
			nc_err_set(error, NC_ERR_PARAM_MSG, err.text);
		}
		rep = nc_reply_error(error);
	}
done:
	configd_error_free(&err);
	free(result);
	free(body);
	free(name);
	free(namespace);
	return rep;
}
