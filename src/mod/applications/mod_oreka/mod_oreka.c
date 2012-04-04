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
	char local_ipv4_str[256];
	char sip_server_addr_str[256];
	char sip_server_ipv4_str[256];
	int sip_server_port;
	switch_sockaddr_t *sip_server_addr;
	switch_socket_t *sip_socket;
	pid_t our_pid;
} globals;

typedef enum {
	FS_OREKA_START,
	FS_OREKA_STOP
} oreka_recording_status_t;

typedef enum {
	FS_OREKA_READ,
	FS_OREKA_WRITE
} oreka_stream_type_t;

static int oreka_write_udp(oreka_session_t *oreka, switch_stream_handle_t *udp)
{
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(oreka->session), SWITCH_LOG_CRIT, "Oreka SIP Packet:\n%s", (const char *)udp->data);
	return 0;
}

static int oreka_send_sip_message(oreka_session_t *oreka, oreka_recording_status_t status, oreka_stream_type_t type)
{
	switch_stream_handle_t sip_header = { 0 };
	switch_stream_handle_t sdp = { 0 };
	switch_stream_handle_t udp_packet = { 0 };
	switch_caller_profile_t *caller_profile = NULL;
	switch_channel_t *channel = NULL;
	const char *method = status == FS_OREKA_START ? "INVITE" : "BYE";
	const char *session_uuid = switch_core_session_get_uuid(oreka->session);
	const char *caller_id_number = NULL;
	const char *caller_id_name = NULL;
	const char *caller_source = NULL;
	const char *caller_destination = NULL;

	SWITCH_STANDARD_STREAM(sip_header);
	SWITCH_STANDARD_STREAM(sdp);
	SWITCH_STANDARD_STREAM(udp_packet);

	channel = switch_core_session_get_channel(oreka->session);
	caller_profile = switch_channel_get_caller_profile(channel);

	/* Get caller meta data */
	caller_source = switch_caller_get_field_by_name(caller_profile, "source");
	caller_id_number = switch_caller_get_field_by_name(caller_profile, "caller_id_number");
	caller_id_name = switch_caller_get_field_by_name(caller_profile, "caller_id_name");
	caller_destination = switch_caller_get_field_by_name(caller_profile, "destination_number");

	/* Fill in the SDP first if this is the beginning */
	if (status == FS_OREKA_START) {
		sdp.write_function(&sdp, "v=0\r\n");
		sdp.write_function(&sdp, "o=freeswitch %s 1 IN IP4 %s\r\n", session_uuid, globals.local_ipv4_str);
		sdp.write_function(&sdp, "c=IN IP4 %s\r\n", globals.sip_server_ipv4_str);
		sdp.write_function(&sdp, "s=Phone Recording (%s)\r\n", type == FS_OREKA_READ ? "RX" : "TX");
		sdp.write_function(&sdp, "i=FreeSWITCH Oreka Recorder (pid=%d)\r\n", globals.our_pid);
		sdp.write_function(&sdp, "m=audio %d RTP/AVP 0\r\n", 0);
		sdp.write_function(&sdp, "a=rtpmap:0 PCMU/8000\r\n");
	}

	/* Request line */
	sip_header.write_function(&sip_header, "%s sip:%s@%s:5060 SIP/2.0\r\n", method, caller_source, globals.local_ipv4_str);

	/* Via */
	sip_header.write_function(&sip_header, "Via: SIP/2.0/UDP %s:5061;branch=z9hG4bK-%s\r\n", globals.local_ipv4_str, session_uuid);

	/* From */
	sip_header.write_function(&sip_header, "From: <sip:%s@%s:5061;tag=1>\r\n", caller_id_number, globals.local_ipv4_str);

	/* To */
	sip_header.write_function(&sip_header, "To: <sip:%s@%s:5060>\r\n", caller_destination, globals.local_ipv4_str);

	/* Call-ID */
	sip_header.write_function(&sip_header, "Call-ID: %s\r\n", session_uuid);

	/* CSeq */
	sip_header.write_function(&sip_header, "CSeq: 1 %s\r\n", method);

	/* Contact */
	sip_header.write_function(&sip_header, "Contact: sip:freeswitch@%s:5061\r\n", globals.local_ipv4_str);

	/* Max-Forwards */
	sip_header.write_function(&sip_header, "Max-Forwards: 70\r\n", method);

	/* Subject */
	sip_header.write_function(&sip_header, "Subject: %s %s recording of %s\r\n", 
					status == FS_OREKA_START ? "BEGIN": "END",
					type == FS_OREKA_READ ? "RX" : "TX", caller_id_number);

	if (status == FS_OREKA_START) {
		/* Content-Type */
		sip_header.write_function(&sip_header, "Content-Type: application/sdp\r\n");

	}

	/* Content-Length */
	sip_header.write_function(&sip_header, "Content-Length: %d\r\n", sdp.data_len);

	udp_packet.write_function(&udp_packet, "%s\r\n%s\n", sip_header.data, sdp.data);

	oreka_write_udp(oreka, &udp_packet);

	free(sip_header.data);
	free(sdp.data);
	free(udp_packet.data);

	return 0;
}

static switch_bool_t oreka_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type)
{
	static int count = 0;
	oreka_session_t *oreka = user_data;
	switch_core_session_t *session = oreka->session;

	switch (type) {
	case SWITCH_ABC_TYPE_INIT:
		{
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Starting Oreka recording!\n");
			oreka_send_sip_message(oreka, FS_OREKA_START, FS_OREKA_READ);
			oreka_send_sip_message(oreka, FS_OREKA_START, FS_OREKA_WRITE);
		}
		break;
	case SWITCH_ABC_TYPE_CLOSE:
		{
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Done Oreka recording!\n");
			oreka_send_sip_message(oreka, FS_OREKA_STOP, FS_OREKA_READ);
			oreka_send_sip_message(oreka, FS_OREKA_STOP, FS_OREKA_WRITE);
		}
		break;
	case SWITCH_ABC_TYPE_READ:
		{
		}
		break;
	case SWITCH_ABC_TYPE_WRITE:
		{
		}
		break;
	default:
		break;
	}
	count++;
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

#define OREKA_XML_CONFIG "oreka.conf"
static int load_config(void)
{
	switch_xml_t cfg, xml, settings, param;
	if (!(xml = switch_xml_open_cfg(OREKA_XML_CONFIG, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to open XML configuration '%s'\n", OREKA_XML_CONFIG);
		return -1;
	}

	if ((settings = switch_xml_child(cfg, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Found parameter %s=%s\n", var, val);
			if (!strcasecmp(var, "sip-server-addr")) {
				snprintf(globals.sip_server_addr_str, sizeof(globals.sip_server_addr_str), "%s", val);
			} else if (!strcasecmp(var, "sip-server-port")) {
				globals.sip_server_port = atoi(val);
			}
		}
	}

	switch_xml_free(xml);
	return 0;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_oreka_load)
{
	switch_application_interface_t *app_interface = NULL;
	int mask = 0;
#if 0
	switch_status_t status = SWITCH_STATUS_FALSE;
	int x = 0;
	switch_size_t len = 0;
	switch_size_t ilen = 0;
	char dummy_output[] = "Parangaricutirimicuaro";
	char dummy_input[sizeof(dummy_output)] = "";
	switch_sockaddr_t *from_addr = NULL;
#endif

	memset(&globals, 0, sizeof(globals));

	if (load_config()) {
		return SWITCH_STATUS_UNLOAD;
	}

	if (zstr(globals.sip_server_addr_str)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "No sip server address specified!\n");
		return SWITCH_STATUS_UNLOAD;
	}

	if (!globals.sip_server_port) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "No sip server port specified!\n");
		return SWITCH_STATUS_UNLOAD;
	}

	//switch_sockaddr_info_get(&globals.sip_server_addr, "sigchld.sangoma.local", SWITCH_UNSPEC, 5080, 0, pool);
	switch_sockaddr_info_get(&globals.sip_server_addr, globals.sip_server_addr_str, SWITCH_UNSPEC, globals.sip_server_port, 0, pool);

	if (!globals.sip_server_addr) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid sip server address specified: %s!\n", globals.sip_server_addr_str);
		return SWITCH_STATUS_UNLOAD;
	}

	if (switch_socket_create(&globals.sip_socket, switch_sockaddr_get_family(globals.sip_server_addr), SOCK_DGRAM, 0, pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create socket!\n");
		return SWITCH_STATUS_UNLOAD;
	}

	switch_find_local_ip(globals.local_ipv4_str, sizeof(globals.local_ipv4_str), &mask, AF_INET);
	switch_get_addr(globals.sip_server_ipv4_str, sizeof(globals.sip_server_ipv4_str), globals.sip_server_addr);
	globals.our_pid = getpid();

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, 
		"Loading mod_oreka, sip_server_addr=%s, sip_server_ipv4_str=%s, sip_server_port=%d, local_ipv4_str=%s\n", 
		globals.sip_server_addr_str, globals.sip_server_ipv4_str, globals.sip_server_port, globals.local_ipv4_str);

#if 0
	if (switch_socket_bind(globals.sip_socket, globals.sip_addr) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to bind to SIP address: %s!\n", strerror(errno));
		return SWITCH_STATUS_UNLOAD;
	}
#endif

#if 0
	len = sizeof(dummy_output);
#ifndef WIN32
	switch_socket_opt_set(globals.sip_socket, SWITCH_SO_NONBLOCK, TRUE);

	status = switch_socket_sendto(globals.sip_socket, globals.sip_addr, 0, (void *)dummy_output, &len);
	if (status != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to send UDP message! (status=%d)\n", status);
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
