#include <assert.h>
#include <stdlib.h>
#include <wlr/util/log.h>
#include "backend/rdp.h"

static int rdp_listener_activity(int fd, uint32_t mask, void *data) {
	freerdp_listener *listener = (freerdp_listener *)data;
	if (!(mask & WL_EVENT_READABLE)) {
		return 0;
	}
	if (!listener->CheckFileDescriptor(listener)) {
		wlr_log(WLR_ERROR, "Failed to check FreeRDP file descriptor");
		return -1;
	}
	return 0;
}

static int rdp_incoming_peer(
		freerdp_listener *listener, freerdp_peer *client) {
	//struct wlr_rdp_backend *backend =
	//	(struct wlr_rdp_backend *)listener->param4;
	wlr_log(WLR_DEBUG, "New RDP connection");
	return 1;
}

bool rdp_configure_listener(struct wlr_rdp_backend *backend) {
	backend->listener = freerdp_listener_new();
	backend->listener->PeerAccepted = rdp_incoming_peer;
	backend->listener->param4 = backend;
	if (!backend->listener->Open(backend->listener, "127.0.0.1", 3389)) {
		wlr_log(WLR_ERROR, "Failed to bind to RDP socket");
		return false;
	}
	int rcount = 0;
	void *rfds[MAX_FREERDP_FDS];
	if (!backend->listener->GetFileDescriptor(
				backend->listener, rfds, &rcount)) {
		wlr_log(WLR_ERROR, "Failed to get FreeRDP file descriptors");
		return false;
	}
	struct wl_event_loop *event_loop =
		wl_display_get_event_loop(backend->display);
	int i;
	for (i = 0; i < rcount; ++i) {
		int fd = (int)(long)(rfds[i]);
		backend->listener_events[i] = wl_event_loop_add_fd(
				event_loop, fd, WL_EVENT_READABLE, rdp_listener_activity,
				backend->listener);
	}
	for (; i < MAX_FREERDP_FDS; ++i) {
		backend->listener_events[i] = NULL;
	}
	return true;
}
