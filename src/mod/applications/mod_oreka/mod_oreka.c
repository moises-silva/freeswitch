/* 
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2011, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Oreka Recording Module
 *
 * The Initial Developer of the Original Code is
 * Moises Silva <moises.silva@gmail.com>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 * Moises Silva <moises.silva@gmail.com>
 *
 * mod_oreka -- Module for Media Recording with Oreka
 *
 */

#include <switch.h>

#define OREKA_PRIVATE "_oreka_"
#define OREKA_BUG_NAME "oreka"

SWITCH_MODULE_LOAD_FUNCTION(mod_oreka_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_oreka_shutdown);
SWITCH_MODULE_DEFINITION(mod_oreka, mod_oreka_load, mod_oreka_shutdown, NULL);

typedef struct oreka_session_s {
	switch_core_session_t *session;
} oreka_session_t;

struct {
	switch_sockaddr_t *sip_addr;
	switch_socket_t *sip_socket;
} globals;

static switch_bool_t oreka_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type)
{
	oreka_session_t *oreka = user_data;
	switch_core_session_t *session = oreka->session;

	switch (type) {
	case SWITCH_ABC_TYPE_INIT:
		{
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "Starting Oreka recording!\n");
		}
		break;
	case SWITCH_ABC_TYPE_CLOSE:
		{
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "Done Oreka recording!\n");
		}
		break;
	case SWITCH_ABC_TYPE_READ:
	case SWITCH_ABC_TYPE_WRITE:
		break;
	default:
		break;
	}
	return SWITCH_TRUE;
}

SWITCH_STANDARD_APP(oreka_start_function)
{
	switch_media_bug_t *bug = NULL;
	switch_status_t status;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	oreka_session_t *oreka = NULL;
	char *argv[6];
	int argc;
	char *lbuf = NULL;

	if ((bug = (switch_media_bug_t *) switch_channel_get_private(channel, "_oreka_"))) {
		if (!zstr(data) && !strcasecmp(data, "stop")) {
			switch_channel_set_private(channel, OREKA_PRIVATE, NULL);
			switch_core_media_bug_remove(session, &bug);
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "Cannot run oreka recording 2 times on the same session!\n");
		}
		return;
	}

	oreka = switch_core_session_alloc(session, sizeof(*oreka));

	assert(oreka != NULL);

	if (data && (lbuf = switch_core_session_strdup(session, data))
		&& (argc = switch_separate_string(lbuf, ' ', argv, (sizeof(argv) / sizeof(argv[0]))))) {
#if 0
		if (!strncasecmp(argv[x], "server", sizeof("server"))) {
			/* parse server=192.168.1.144 string */
		}
#endif
	}

	oreka->session = session;
	status = switch_core_media_bug_add(session, OREKA_BUG_NAME, NULL, oreka_callback, oreka, 0, 
			(SMBF_READ_STREAM | SMBF_WRITE_STREAM | SMBF_ANSWER_REQ), &bug);
	if (status != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Failed to attach oreka to media stream!\n");
		return;
	}

	switch_channel_set_private(channel, OREKA_PRIVATE, bug);

}

SWITCH_MODULE_LOAD_FUNCTION(mod_oreka_load)
{
	switch_status_t status = SWITCH_STATUS_FALSE;
	switch_application_interface_t *app_interface = NULL;
	switch_size_t len = 0;
	switch_size_t ilen = 0;
	int x = 0;
	switch_sockaddr_t *from_addr = NULL;
	char dummy_output[] = "Parangaricutirimicuaro";
	char dummy_input[sizeof(dummy_output)] = "";

	memset(&globals, 0, sizeof(globals));

	switch_sockaddr_info_get(&globals.sip_addr, "sigchld.sangoma.local", SWITCH_UNSPEC, 5060, 0, pool);

	if (switch_socket_create(&globals.sip_socket, switch_sockaddr_get_family(globals.sip_addr), SOCK_DGRAM, 0, pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create socket!\n");
		return SWITCH_STATUS_UNLOAD;
	}

	if (switch_socket_opt_set(globals.sip_socket, SWITCH_SO_REUSEADDR, 1) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to set socket option!\n");
		return SWITCH_STATUS_UNLOAD;
	}

	if (switch_socket_bind(globals.sip_socket, globals.sip_addr) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to bind to SIP address: %s!\n", strerror(errno));
		return SWITCH_STATUS_UNLOAD;
	}

	len = sizeof(dummy_output);
#ifndef WIN32
	switch_socket_opt_set(globals.sip_socket, SWITCH_SO_NONBLOCK, TRUE);

	status = switch_socket_sendto(globals.sip_socket, globals.sip_addr, 0, (void *)dummy_output, &len);
	if (status != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to send UDP message! (status=%d)\n", status);
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Sent message of length %lu!\n", len);
	}

	status = switch_sockaddr_create(&from_addr, pool);
	if (status != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to creat socket address\n");
	}
	while (!ilen) {
		ilen = sizeof(dummy_input);
		status = switch_socket_recvfrom(from_addr, globals.sip_socket, 0, (void *)dummy_input, &ilen);
		if (status != SWITCH_STATUS_SUCCESS && status != SWITCH_STATUS_BREAK) {
			break;
		}

		if (++x > 1000) {
			break;
		}

		switch_cond_next();
	}

	switch_socket_opt_set(globals.sip_socket, SWITCH_SO_NONBLOCK, FALSE);
#endif

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	SWITCH_ADD_APP(app_interface, "oreka_record", "Send media to Oreka recording server", "Send media to Oreka recording server", 
	oreka_start_function, "[stop]", SAF_NONE); 
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_oreka_shutdown)
{
	switch_socket_close(globals.sip_socket);
	return SWITCH_STATUS_UNLOAD;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:nil
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4:
 */
