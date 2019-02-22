#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>
#include <wlr/types/wlr_output.h>
#include <wlr/util/log.h>
#include "backend/rdp.h"

static BOOL xf_peer_capabilities(freerdp_peer *client) {
	return TRUE;
}

static BOOL xf_peer_post_connect(freerdp_peer *client) {
	return TRUE;
}

static BOOL xf_peer_activate(freerdp_peer *client) {
	struct wlr_rdp_peer_context *context =
		(struct wlr_rdp_peer_context *)client->context;
	struct wlr_rdp_backend *backend = context->backend;
	rdpSettings *settings = client->settings;

	if (!settings->SurfaceCommandsEnabled) {
		wlr_log(WLR_ERROR, "RDP peer does not support SurfaceCommands");
		return FALSE;
	}

	context->output = wlr_rdp_output_create(backend,
			(int)settings->DesktopWidth, (int)settings->DesktopHeight);
	rfx_context_reset(context->rfx_context,
			context->output->wlr_output.width,
			context->output->wlr_output.height);
	nsc_context_reset(context->nsc_context,
			context->output->wlr_output.width,
			context->output->wlr_output.height);

	if (context->flags & RDP_PEER_ACTIVATED) {
		return TRUE;
	}

	// TODO: Configure input devices

	return TRUE;
}

static int xf_suppress_output(rdpContext *context,
		BYTE allow, const RECTANGLE_16 *area) {
	struct wlr_rdp_peer_context *peer_context =
		(struct wlr_rdp_peer_context *)context;
	if (allow) {
		peer_context->flags |= RDP_PEER_OUTPUT_ENABLED;
	} else {
		peer_context->flags &= (~RDP_PEER_OUTPUT_ENABLED);
	}
	return true;
}

static int xf_input_synchronize_event(rdpInput *input, UINT32 flags) {
	// TODO
	return true;
}

static int xf_input_mouse_event(rdpInput *input,
		UINT16 flags, UINT16 x, UINT16 y) {
	// TODO
	return true;
}

static int xf_input_extended_mouse_event(
		rdpInput *input, UINT16 flags, UINT16 x, UINT16 y) {
	// TODO
	return true;
}

static int xf_input_keyboard_event(rdpInput *input, UINT16 flags, UINT16 code) {
	// TODO
	return true;
}

static int xf_input_unicode_keyboard_event(rdpInput *input,
		UINT16 flags, UINT16 code) {
	wlr_log(WLR_DEBUG, "Unhandled RDP unicode keyboard event "
			"(flags:0x%X code:0x%X)\n", flags, code);
	return true;
}

static int rdp_client_activity(int fd, uint32_t mask, void *data) {
	freerdp_peer *client = (freerdp_peer *)data;
	if (!client->CheckFileDescriptor(client)) {
		wlr_log(WLR_ERROR,
				"Unable to check client file descriptor for %p", client);
		freerdp_peer_context_free(client);
		freerdp_peer_free(client);
	}
	return 0;
}

static int rdp_peer_context_new(
		freerdp_peer *client, struct wlr_rdp_peer_context *context) {
	context->peer = client;
	context->flags = RDP_PEER_OUTPUT_ENABLED;
	context->rfx_context = rfx_context_new(TRUE);
	if (!context->rfx_context) {
		return false;
	}
	context->rfx_context->mode = RLGR3;
	context->rfx_context->width = client->settings->DesktopWidth;
	context->rfx_context->height = client->settings->DesktopHeight;
	rfx_context_set_pixel_format(context->rfx_context, PIXEL_FORMAT_BGRA32);

	context->nsc_context = nsc_context_new();
	if (!context->nsc_context) {
		rfx_context_free(context->rfx_context);
		return false;
	}

	nsc_context_set_pixel_format(context->nsc_context, PIXEL_FORMAT_BGRA32);

	context->encode_stream = Stream_New(NULL, 65536);
	if (!context->encode_stream) {
		nsc_context_free(context->nsc_context);
		rfx_context_free(context->rfx_context);
		return false;
	}
	return true;
}

static void rdp_peer_context_free(
		freerdp_peer *client, struct wlr_rdp_peer_context *context) {
	if (!context) {
		return;
	}
	for (int i = 0; i < MAX_FREERDP_FDS; ++i) {
		if (context->events[i]) {
			wl_event_source_remove(context->events[i]);
		}
	}
	if (context->flags & RDP_PEER_ACTIVATED) {
		// TODO: destroy keyboard/pointer/output
	}

	wl_list_remove(&context->link);
	wlr_output_destroy(&context->output->wlr_output);

	Stream_Free(context->encode_stream, TRUE);
	nsc_context_free(context->nsc_context);
	rfx_context_free(context->rfx_context);
	free(context->rfx_rects);
}

int rdp_peer_init(freerdp_peer *client,
		struct wlr_rdp_backend *backend) {
	client->ContextSize = sizeof(struct wlr_rdp_peer_context);
	client->ContextNew = (psPeerContextNew)rdp_peer_context_new;
	client->ContextFree = (psPeerContextFree)rdp_peer_context_free;
	freerdp_peer_context_new(client);

	struct wlr_rdp_peer_context *peer_context =
		(struct wlr_rdp_peer_context *)client->context;
	peer_context->backend = backend;

	client->settings->CertificateFile = strdup(backend->tls_cert_path);
	client->settings->PrivateKeyFile = strdup(backend->tls_key_path);
	client->settings->NlaSecurity = FALSE;

	if (!client->Initialize(client)) {
		wlr_log(WLR_ERROR, "Failed to initialize FreeRDP peer");
		goto err_init;
	}

	client->settings->OsMajorType = OSMAJORTYPE_UNIX;
	client->settings->OsMinorType = OSMINORTYPE_PSEUDO_XSERVER;
	client->settings->ColorDepth = 32;
	client->settings->RefreshRect = TRUE;
	client->settings->RemoteFxCodec = TRUE;
	client->settings->NSCodec = TRUE;
	client->settings->FrameMarkerCommandEnabled = TRUE;
	client->settings->SurfaceFrameMarkerEnabled = TRUE;

	client->Capabilities = xf_peer_capabilities;
	client->PostConnect = xf_peer_post_connect;
	client->Activate = xf_peer_activate;

	client->update->SuppressOutput = (pSuppressOutput)xf_suppress_output;

	client->input->SynchronizeEvent = xf_input_synchronize_event;
	client->input->MouseEvent = xf_input_mouse_event;
	client->input->ExtendedMouseEvent = xf_input_extended_mouse_event;
	client->input->KeyboardEvent = xf_input_keyboard_event;
	client->input->UnicodeKeyboardEvent = xf_input_unicode_keyboard_event;

	int rcount = 0;
	void *rfds[MAX_FREERDP_FDS];
	if (!client->GetFileDescriptor(client, rfds, &rcount)) {
		wlr_log(WLR_ERROR, "Unable to retrieve client file descriptors");
		goto err_init;
	}
	struct wl_event_loop *event_loop =
		wl_display_get_event_loop(backend->display);
	int i;
	for (i = 0; i < rcount; ++i) {
		int fd = (int)(long)(rfds[i]);
		peer_context->events[i] = wl_event_loop_add_fd(
				event_loop, fd, WL_EVENT_READABLE, rdp_client_activity,
				client);
	}
	for (; i < MAX_FREERDP_FDS; ++i) {
		peer_context->events[i] = NULL;
	}

	wl_list_insert(&backend->clients, &peer_context->link);
	return 0;

err_init:
	client->Close(client);
	return -1;
}
