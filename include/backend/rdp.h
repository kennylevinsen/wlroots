#ifndef BACKEND_RDP_H
#define BACKEND_RDP_H
#include <wlr/backend/rdp.h>
#include <wlr/backend/interface.h>
#include <freerdp/freerdp.h>
#include <freerdp/listener.h>
#include <freerdp/update.h>
#include <freerdp/input.h>
#include <freerdp/codec/color.h>
#include <freerdp/codec/rfx.h>
#include <freerdp/codec/nsc.h>
#include <freerdp/locale/keyboard.h>

#define MAX_FREERDP_FDS 64

struct wlr_rdp_backend {
	struct wlr_backend backend;
	struct wlr_egl egl;
	struct wlr_renderer *renderer;
	struct wl_display *display;
	struct wl_listener display_destroy;
	bool started;

	freerdp_listener *listener;
	struct wl_event_source *listener_events[MAX_FREERDP_FDS];
};

struct wlr_rdp_backend *rdp_backend_from_backend(
	struct wlr_backend *wlr_backend);
bool rdp_configure_listener(struct wlr_rdp_backend *backend);

#endif
