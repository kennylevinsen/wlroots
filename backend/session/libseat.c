#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <wayland-server-core.h>
#include <wlr/backend/session/interface.h>
#include <wlr/config.h>
#include <wlr/util/log.h>
#include "util/signal.h"

#include <libseat.h>

const struct session_impl session_libseat;

struct libseat_session {
	struct wlr_session base;

	struct libseat *seat;
	struct wl_event_source *event;

	bool signal;
	bool activated;
};

static void handle_enable_seat(struct libseat *seat, void *data) {
	struct libseat_session *session = data;
	session->activated = true;
	session->base.active = true;

	// The session signal is muted until setup is complete, as it might not be
	// prepared by the caller yet.
	if (session->signal) {
		wlr_signal_emit_safe(&session->base.session_signal, session);
	}
}

static void handle_disable_seat(struct libseat *seat, void *data) {
	struct libseat_session *session = data;
	session->activated = false;
	session->base.active = false;

	// The session signal is muted until setup is complete, as it might not be
	// prepared by the caller yet.
	if (session->signal) {
		wlr_signal_emit_safe(&session->base.session_signal, session);
	}
	libseat_disable_seat(session->seat);
}

static int libseat_event(int fd, uint32_t mask, void *data) {
	struct libseat *seat = data;
	libseat_dispatch(seat, 0);
	return 1;
}

static struct libseat_seat_listener seat_listener = {
	.enable_seat = handle_enable_seat,
	.disable_seat = handle_disable_seat,
};

static struct libseat_session *libseat_session_from_session(
		struct wlr_session *base) {
	assert(base->impl == &session_libseat);
	return (struct libseat_session *)base;
}

static struct wlr_session *libseat_session_create(struct wl_display *disp) {
	struct libseat_session *session = calloc(1, sizeof(*session));
	if (!session) {
		wlr_log(WLR_ERROR, "Allocation failed: %s", strerror(errno));
		return NULL;
	}

	session->seat = libseat_open_seat(&seat_listener, session);
	if (session->seat == NULL) {
		wlr_log(WLR_ERROR, "Unable to create seat: %s\n", strerror(errno));
		goto error;
	}

	const char *seat_name = libseat_seat_name(session->seat);
	if (seat_name == NULL) {
		wlr_log(WLR_ERROR, "Unable to get seat info: %s\n", strerror(errno));
		goto error;
	}
	snprintf(session->base.seat, sizeof(session->base.seat), "%s", seat_name);

	struct wl_event_loop *event_loop = wl_display_get_event_loop(disp);
	session->event = wl_event_loop_add_fd(event_loop, libseat_get_fd(session->seat),
		WL_EVENT_READABLE, libseat_event, session->seat);

	if (libseat_dispatch(session->seat, 0) == -1 && errno != EAGAIN) {
		wlr_log(WLR_ERROR, "libseat dispatch failed: %s\n", strerror(errno));
		goto error;
	}

	if (!session->activated) {
		wlr_log(WLR_INFO, "Waiting for seat activation on %s", session->base.seat);
	}

	while (!session->activated) {
		if (wl_event_loop_dispatch(event_loop, -1) == -1) {
			wlr_log(WLR_ERROR, "libseat dispatch failed: %s\n", strerror(errno));
			goto error;
		}
	}

	wlr_log(WLR_INFO, "Successfully loaded libseat session");
	session->base.impl = &session_libseat;
	session->signal = true;
	return &session->base;

error:
	if (session->seat != NULL) {
		libseat_close_seat(session->seat);
		session->seat = NULL;
	}
	if (session->event != NULL) {
		wl_event_source_remove(session->event);
		session->event = NULL;
	}
	free(session);
	return NULL;
}

static void libseat_session_destroy(struct wlr_session *base) {
	struct libseat_session *session = libseat_session_from_session(base);

	libseat_close_seat(session->seat);
	wl_event_source_remove(session->event);
	free(session);
}

static int libseat_session_open_device(struct wlr_session *base, const char *path, int *device_id) {
	struct libseat_session *session = libseat_session_from_session(base);

	int fd;
	*device_id = libseat_open_device(session->seat, path, &fd);
	if (*device_id == -1) {
		wlr_log(WLR_ERROR, "Failed to open device '%s': %s", path, strerror(errno));
		return -1;
	}

	return fd;
}

static void libseat_session_close_device(struct wlr_session *base, int fd, int device_id) {
	struct libseat_session *session = libseat_session_from_session(base);

	if (libseat_close_device(session->seat, device_id) == -1) {
		wlr_log(WLR_ERROR, "Failed to close device '%d': %s", device_id, strerror(errno));
	}
	close(fd);
}

static bool libseat_change_vt(struct wlr_session *base, unsigned vt) {
	struct libseat_session *session = libseat_session_from_session(base);
	return libseat_switch_session(session->seat, vt);
}

const struct session_impl session_libseat = {
	.create = libseat_session_create,
	.destroy = libseat_session_destroy,
	.open = libseat_session_open_device,
	.close = libseat_session_close_device,
	.change_vt = libseat_change_vt,
};
