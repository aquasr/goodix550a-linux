// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Goodix 27c6:550a libfprint Rust capture/enrollment/verification bridge.
 *
 * USB ownership and asynchronous scheduling stay in libfprint. Goodix wire
 * construction/parsing, D2 session state, FDT/GetImage ordering, image
 * authentication, decryption, CRC validation, GF3258 reconstruction, and
 * persisted-gallery verification stay in the Rust core behind the narrow bridge API.
 */

#define FP_COMPONENT "goodix550a"

#include "drivers_api.h"
#include "fpi-image.h"
#include <goodix550a_bridge.h>
#include <string.h>

#define GOODIX550A_USB_VID 0x27c6
#define GOODIX550A_USB_PID 0x550a
#define GOODIX550A_INTERFACE 0
#define GOODIX550A_EP_OUT 0x01
#define GOODIX550A_EP_IN 0x83
#define GOODIX550A_TIMEOUT_MS 1000
#define GOODIX550A_USB_BLOCK_SIZE 64
#define GOODIX550A_RECOVERY_OUT_MAX 264
#define GOODIX550A_IMAGE_WIDTH 80
#define GOODIX550A_IMAGE_HEIGHT 64
#define GOODIX550A_IMAGE_PIXELS (GOODIX550A_IMAGE_WIDTH * GOODIX550A_IMAGE_HEIGHT)
#define GOODIX550A_ENROLL_STAGES 12
#define GOODIX550A_PRINT_VERSION 1u
#define GOODIX550A_PRINT_TYPE "(uay)"

#define GOODIX550A_BOOTSTRAP_HANDOFF_USEC (10 * G_USEC_PER_SEC)

typedef struct
{
  GMutex mutex;
  gchar *platform_id;
  gint64 expires_at_us;
} Goodix550aBootstrapHandoff;

static Goodix550aBootstrapHandoff bootstrap_handoff;

static void
bootstrap_handoff_clear_locked (void)
{
  g_clear_pointer (&bootstrap_handoff.platform_id, g_free);
  bootstrap_handoff.expires_at_us = 0;
}

static void
bootstrap_handoff_arm (FpDevice *device)
{
  GUsbDevice *usb_device = fpi_device_get_usb_device (device);
  const gchar *platform_id = g_usb_device_get_platform_id (usb_device);

  if (!platform_id || platform_id[0] == '\0')
    {
      fp_warn ("cannot arm GF3258 post-bootstrap handoff without a USB platform ID");
      return;
    }

  g_mutex_lock (&bootstrap_handoff.mutex);
  bootstrap_handoff_clear_locked ();
  bootstrap_handoff.platform_id = g_strdup (platform_id);
  bootstrap_handoff.expires_at_us = g_get_monotonic_time () + GOODIX550A_BOOTSTRAP_HANDOFF_USEC;
  g_mutex_unlock (&bootstrap_handoff.mutex);

  fp_info ("armed GF3258 post-bootstrap handoff for %s", platform_id);
}

static gboolean
bootstrap_handoff_take (FpDevice *device)
{
  GUsbDevice *usb_device = fpi_device_get_usb_device (device);
  const gchar *platform_id = g_usb_device_get_platform_id (usb_device);
  gint64 now = g_get_monotonic_time ();
  gboolean matched = FALSE;

  if (!platform_id || platform_id[0] == '\0')
    return FALSE;

  g_mutex_lock (&bootstrap_handoff.mutex);

  if (bootstrap_handoff.platform_id && bootstrap_handoff.expires_at_us <= now)
    bootstrap_handoff_clear_locked ();

  if (bootstrap_handoff.platform_id &&
      g_strcmp0 (bootstrap_handoff.platform_id, platform_id) == 0)
    {
      matched = TRUE;
      bootstrap_handoff_clear_locked ();
    }

  g_mutex_unlock (&bootstrap_handoff.mutex);
  return matched;
}

struct _FpiDeviceGoodix550a
{
  FpDevice parent;

  FpiSsm *probe_ssm;
  FpiSsm *open_ssm;
  Goodix550aBridgeBootstrap *bootstrap;
  Goodix550aBridgeRecovery *recovery;
  Goodix550aBridgeCapture *capture;
  Goodix550aBridgeEnrollment *enrollment;
  Goodix550aBridgeVerification *verification;
  gboolean claimed;
  gboolean mcu_power_lost;
  Goodix550aBridgeFirmware firmware;
  gboolean bootstrap_pre_reset_complete;
  gboolean bootstrap_old_usb_invalid;
  gboolean post_bootstrap_handoff;
  gsize bootstrap_f0_chunks_sent;
  guint8 bootstrap_firmware_check_result;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodix550a, fpi_device_goodix550a, FPI, DEVICE_GOODIX550A, FpDevice);
G_DEFINE_TYPE (FpiDeviceGoodix550a, fpi_device_goodix550a, FP_TYPE_DEVICE);

typedef enum
{
  OPEN_SEND_VERSION,
  OPEN_READ_ACK,
  OPEN_READ_VERSION,
  OPEN_NUM_STATES,
} OpenState;

typedef enum
{
  PROBE_SEND_VERSION,
  PROBE_READ_ACK,
  PROBE_READ_VERSION,
  PROBE_POSTBOOT_RESET_WRITE,
  PROBE_POSTBOOT_RESET_ACK,
  PROBE_POSTBOOT_RESET_COMPLETION,
  PROBE_POSTBOOT_CHIP_ID_WRITE,
  PROBE_POSTBOOT_CHIP_ID_ACK,
  PROBE_POSTBOOT_CHIP_ID_COMPLETION,
  PROBE_NUM_STATES,
} ProbeState;

static void bootstrap_schedule_next (FpiDeviceGoodix550a *self);
static void recovery_schedule_next (FpiDeviceGoodix550a *self);
static void capture_schedule_next (FpiDeviceGoodix550a *self);
static void enrollment_schedule_next (FpiDeviceGoodix550a *self);
static void verification_schedule_next (FpiDeviceGoodix550a *self);

static GError *
protocol_error (const gchar *message)
{
  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "%s", message);
}

static GError *
bridge_error (const gchar *operation,
              gint         status)
{
  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                   "%s: %s",
                                   operation,
                                   goodix550a_bridge_status_message (status));
}

static GError *
capture_bridge_error (FpiDeviceGoodix550a *self,
                      const gchar         *operation,
                      gint                 status)
{
  const gchar *detail = self->capture ? goodix550a_bridge_capture_last_error (self->capture) : NULL;

  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                   "%s: %s (%s)",
                                   operation,
                                   detail ? detail : "capture bridge unavailable",
                                   goodix550a_bridge_status_message (status));
}

static GError *
enrollment_bridge_error (FpiDeviceGoodix550a *self,
                         const gchar         *operation,
                         gint                 status)
{
  const gchar *detail = self->enrollment ? goodix550a_bridge_enrollment_last_error (self->enrollment) : NULL;

  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                   "%s: %s (%s)",
                                   operation,
                                   detail ? detail : "enrollment bridge unavailable",
                                   goodix550a_bridge_status_message (status));
}

static GError *
verification_bridge_error (FpiDeviceGoodix550a *self,
                           const gchar         *operation,
                           gint                 status)
{
  const gchar *detail = self->verification ? goodix550a_bridge_verification_last_error (self->verification) : NULL;

  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                   "%s: %s (%s)",
                                   operation,
                                   detail ? detail : "verification bridge unavailable",
                                   goodix550a_bridge_status_message (status));
}

static void bootstrap_reset_schedule (FpiDeviceGoodix550a *self);

static void
bootstrap_reset_fail (FpiDeviceGoodix550a *self,
                      GError              *error)
{
  if (self->probe_ssm)
    fpi_ssm_mark_failed (self->probe_ssm, error);
  else if (self->open_ssm)
    fpi_ssm_mark_failed (self->open_ssm, error);
  else
    g_error_free (error);
}

static void
bootstrap_release_old_usb (FpiDeviceGoodix550a *self)
{
  g_autoptr(GError) release_error = NULL;

  self->bootstrap_old_usb_invalid = TRUE;

  if (!self->claimed)
    return;

  if (!g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (self)),
                                       GOODIX550A_INTERFACE,
                                       0,
                                       &release_error))
    fp_dbg ("old IAP USB interface was already unavailable after bootstrap reset: %s",
            release_error->message);

  self->claimed = FALSE;
}

static void
bootstrap_reset_ack_cb (FpiUsbTransfer *transfer,
                        FpDevice       *device,
                        gpointer        user_data,
                        GError         *error)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  Goodix550aBridgeAck ack = { 0 };
  gint status;

  (void) user_data;

  if (error)
    {
      bootstrap_reset_fail (self, error);
      return;
    }

  status = goodix550a_bridge_parse_bootstrap_reset_ack (transfer->buffer,
                                                         transfer->actual_length,
                                                         &ack);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      bootstrap_reset_fail (self,
                            bridge_error ("Rust bootstrap A2 ACK parser failed", status));
      return;
    }

  fp_info ("Rust-core cold-bootstrap reset acknowledged: flags=0x%02x mcu_power_lost=%s",
           ack.flags,
           ack.mcu_power_lost ? "true" : "false");

  bootstrap_handoff_arm (device);
  bootstrap_release_old_usb (self);

  bootstrap_reset_fail (self,
                        fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                  "GF3258 IAP bootstrap reset completed; discarding the old probe instance for APP re-enumeration"));
}

static void
bootstrap_reset_out_cb (FpiUsbTransfer *transfer,
                        FpDevice       *device,
                        gpointer        user_data,
                        GError         *error)
{
  FpiUsbTransfer *next;

  (void) transfer;
  (void) user_data;

  if (error)
    {
      bootstrap_reset_fail (FPI_DEVICE_GOODIX550A (device), error);
      return;
    }

  next = fpi_usb_transfer_new (device);
  fpi_usb_transfer_fill_bulk (next, GOODIX550A_EP_IN, GOODIX550A_USB_BLOCK_SIZE);
  fpi_usb_transfer_submit (next,
                           GOODIX550A_TIMEOUT_MS,
                           fpi_device_get_cancellable (device),
                           bootstrap_reset_ack_cb,
                           NULL);
}

static void
bootstrap_reset_schedule (FpiDeviceGoodix550a *self)
{
  FpiUsbTransfer *transfer;
  gint status;

  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk (transfer, GOODIX550A_EP_OUT, GOODIX550A_USB_BLOCK_SIZE);

  status = goodix550a_bridge_build_bootstrap_reset_request (transfer->buffer,
                                                             GOODIX550A_USB_BLOCK_SIZE);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      fpi_usb_transfer_unref (transfer);
      bootstrap_reset_fail (self,
                            bridge_error ("Rust bootstrap A2 request builder failed", status));
      return;
    }

  fpi_usb_transfer_set_short_error (transfer, TRUE);
  fp_info ("Rust-core cold-bootstrap F4 accepted; submitting post-bootstrap reset");
  fpi_usb_transfer_submit (transfer,
                           GOODIX550A_TIMEOUT_MS,
                           fpi_device_get_cancellable (FP_DEVICE (self)),
                           bootstrap_reset_out_cb,
                           NULL);
}

static GError *
bootstrap_bridge_error (FpiDeviceGoodix550a *self,
                        const gchar         *operation,
                        gint                 status)
{
  const gchar *detail = self->bootstrap ? goodix550a_bridge_bootstrap_last_error (self->bootstrap) : NULL;

  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                   "%s: %s (%s)",
                                   operation,
                                   detail ? detail : "bootstrap bridge unavailable",
                                   goodix550a_bridge_status_message (status));
}

static void
bootstrap_clear (FpiDeviceGoodix550a *self)
{
  if (!self->bootstrap)
    return;

  goodix550a_bridge_bootstrap_free (self->bootstrap);
  self->bootstrap = NULL;
}

static void
bootstrap_fail (FpiDeviceGoodix550a *self,
                GError              *error)
{
  bootstrap_clear (self);
  self->bootstrap_pre_reset_complete = FALSE;

  if (self->probe_ssm)
    fpi_ssm_mark_failed (self->probe_ssm, error);
  else if (self->open_ssm)
    fpi_ssm_mark_failed (self->open_ssm, error);
  else
    g_error_free (error);
}

static void
bootstrap_finish_success (FpiDeviceGoodix550a *self)
{
  Goodix550aBridgeBootstrapInfo info = { 0 };
  gint status;

  status = goodix550a_bridge_bootstrap_result (self->bootstrap, &info);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      bootstrap_fail (self,
                      bootstrap_bridge_error (self,
                                              "Rust cold-bootstrap result failed",
                                              status));
      return;
    }

  self->bootstrap_f0_chunks_sent = info.f0_chunks_sent;
  self->bootstrap_firmware_check_result = (guint8) info.firmware_check_result;
  self->bootstrap_pre_reset_complete = TRUE;

  fp_info ("Rust-core cold bootstrap pre-reset complete: F0 chunks=%zu F4 result=0x%02x",
           info.f0_chunks_sent,
           info.firmware_check_result);

  bootstrap_clear (self);
  bootstrap_reset_schedule (self);
}

static void
bootstrap_transfer_cb (FpiUsbTransfer *transfer,
                       FpDevice       *device,
                       gpointer        user_data,
                       GError         *error)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  Goodix550aBridgeTransferDirection direction =
    (Goodix550aBridgeTransferDirection) GPOINTER_TO_UINT (user_data);
  const guint8 *input = NULL;
  gsize input_length = 0;
  guint8 advanced = 0;
  gint status;

  if (error)
    {
      bootstrap_fail (self, error);
      return;
    }

  if (direction == GOODIX550A_BRIDGE_TRANSFER_IN)
    {
      input = transfer->buffer;
      input_length = transfer->actual_length;
    }

  status = goodix550a_bridge_bootstrap_complete_transfer (self->bootstrap,
                                                           input,
                                                           input_length,
                                                           &advanced);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      bootstrap_fail (self,
                      bootstrap_bridge_error (self,
                                              "Rust cold-bootstrap transfer parser failed",
                                              status));
      return;
    }

  if (!advanced)
    fp_dbg ("Rust cold bootstrap ignored unrelated IN packet; repeating stage");

  bootstrap_schedule_next (self);
}

static void
bootstrap_schedule_next (FpiDeviceGoodix550a *self)
{
  Goodix550aBridgeBootstrapAction action = { 0 };
  guint8 output[GOODIX550A_USB_BLOCK_SIZE] = { 0 };
  FpiUsbTransfer *transfer;
  gint status;

  if (!self->bootstrap)
    {
      bootstrap_fail (self, protocol_error ("cold-bootstrap scheduler has no Rust engine"));
      return;
    }

  status = goodix550a_bridge_bootstrap_next_action (self->bootstrap,
                                                     &action,
                                                     output,
                                                     sizeof (output));
  if (status != GOODIX550A_BRIDGE_OK)
    {
      bootstrap_fail (self,
                      bootstrap_bridge_error (self,
                                              "Rust cold-bootstrap action failed",
                                              status));
      return;
    }

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_COMPLETE)
    {
      bootstrap_finish_success (self);
      return;
    }

  if (action.direction != GOODIX550A_BRIDGE_TRANSFER_OUT &&
      action.direction != GOODIX550A_BRIDGE_TRANSFER_IN)
    {
      bootstrap_fail (self, protocol_error ("Rust cold bootstrap returned an invalid transfer direction"));
      return;
    }

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT &&
      action.transfer_length > sizeof (output))
    {
      bootstrap_fail (self, protocol_error ("Rust cold-bootstrap OUT action exceeds the 64-byte physical block"));
      return;
    }

  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk (transfer, action.endpoint, action.transfer_length);

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT)
    memcpy (transfer->buffer, output, action.transfer_length);

  fpi_usb_transfer_set_short_error (transfer, action.short_is_error != 0);
  fp_dbg ("Rust bootstrap stage=%u direction=%s endpoint=0x%02x length=%zu timeout=%u",
          action.stage,
          action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT ? "OUT" : "IN",
          (guint) action.endpoint,
          action.transfer_length,
          action.timeout_ms);

  fpi_usb_transfer_submit (transfer,
                           action.timeout_ms,
                           fpi_device_get_cancellable (FP_DEVICE (self)),
                           bootstrap_transfer_cb,
                           GUINT_TO_POINTER (action.direction));
}

static GError *
recovery_bridge_error (FpiDeviceGoodix550a *self,
                       const gchar         *operation,
                       gint                 status)
{
  const gchar *detail = self->recovery ? goodix550a_bridge_recovery_last_error (self->recovery) : NULL;

  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                   "%s: %s (%s)",
                                   operation,
                                   detail ? detail : "recovery bridge unavailable",
                                   goodix550a_bridge_status_message (status));
}

static void
recovery_clear (FpiDeviceGoodix550a *self)
{
  if (!self->recovery)
    return;

  goodix550a_bridge_recovery_free (self->recovery);
  self->recovery = NULL;
}

static void
recovery_fail (FpiDeviceGoodix550a *self,
               GError              *error)
{
  recovery_clear (self);
  if (self->open_ssm)
    fpi_ssm_mark_failed (self->open_ssm, error);
  else
    g_error_free (error);
}

static void
recovery_finish_success (FpiDeviceGoodix550a *self)
{
  Goodix550aBridgeRecoveryInfo info = { 0 };
  gint status;

  status = goodix550a_bridge_recovery_result (self->recovery, &info);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      recovery_fail (self, recovery_bridge_error (self, "Rust ChicagoH result failed", status));
      return;
    }

  fp_info ("Rust-core ChicagoH recovery: tcode=0x%04x diff=0x%04x fdt_offset=%u checksum=0x%04x",
           info.tcode,
           info.diff,
           (guint) info.fdt_offset,
           info.checksum);

  self->mcu_power_lost = FALSE;
  recovery_clear (self);
  fpi_ssm_mark_completed (self->open_ssm);
}

static void
recovery_transfer_cb (FpiUsbTransfer *transfer,
                      FpDevice       *device,
                      gpointer        user_data,
                      GError         *error)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  Goodix550aBridgeTransferDirection direction =
    (Goodix550aBridgeTransferDirection) GPOINTER_TO_UINT (user_data);
  const guint8 *input = NULL;
  gsize input_length = 0;
  guint8 advanced = 0;
  gint status;

  if (error)
    {
      recovery_fail (self, error);
      return;
    }

  if (direction == GOODIX550A_BRIDGE_TRANSFER_IN)
    {
      input = transfer->buffer;
      input_length = transfer->actual_length;
    }

  status = goodix550a_bridge_recovery_complete_transfer (self->recovery,
                                                          input,
                                                          input_length,
                                                          &advanced);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      recovery_fail (self, recovery_bridge_error (self, "Rust ChicagoH transfer parser failed", status));
      return;
    }

  if (!advanced)
    fp_dbg ("Rust ChicagoH recovery ignored unrelated IN packet; repeating stage");

  recovery_schedule_next (self);
}

static void
recovery_schedule_next (FpiDeviceGoodix550a *self)
{
  Goodix550aBridgeRecoveryAction action = { 0 };
  guint8 output[GOODIX550A_RECOVERY_OUT_MAX] = { 0 };
  FpiUsbTransfer *transfer;
  gint status;

  status = goodix550a_bridge_recovery_next_action (self->recovery,
                                                    &action,
                                                    output,
                                                    sizeof (output));
  if (status != GOODIX550A_BRIDGE_OK)
    {
      recovery_fail (self, recovery_bridge_error (self, "Rust ChicagoH action failed", status));
      return;
    }

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_COMPLETE)
    {
      recovery_finish_success (self);
      return;
    }

  if (action.direction != GOODIX550A_BRIDGE_TRANSFER_OUT &&
      action.direction != GOODIX550A_BRIDGE_TRANSFER_IN)
    {
      recovery_fail (self, protocol_error ("Rust ChicagoH returned an invalid transfer direction"));
      return;
    }

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT &&
      action.transfer_length > sizeof (output))
    {
      recovery_fail (self, protocol_error ("Rust ChicagoH OUT action exceeds recovery scratch buffer"));
      return;
    }

  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk (transfer, action.endpoint, action.transfer_length);

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT)
    memcpy (transfer->buffer, output, action.transfer_length);

  fpi_usb_transfer_set_short_error (transfer, action.short_is_error != 0);
  fp_dbg ("Rust recovery stage=%u direction=%s endpoint=0x%02x length=%zu timeout=%u",
          action.stage,
          action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT ? "OUT" : "IN",
          (guint) action.endpoint,
          action.transfer_length,
          action.timeout_ms);

  fpi_usb_transfer_submit (transfer,
                           action.timeout_ms,
                           fpi_device_get_cancellable (FP_DEVICE (self)),
                           recovery_transfer_cb,
                           GUINT_TO_POINTER (action.direction));
}

static void
open_ack_cb (FpiUsbTransfer *transfer,
             FpDevice       *device,
             gpointer        user_data,
             GError         *error)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  Goodix550aBridgeAck ack = { 0 };
  gint status;

  (void) user_data;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  status = goodix550a_bridge_parse_get_version_ack (transfer->buffer,
                                                     transfer->actual_length,
                                                     &ack);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      fpi_ssm_mark_failed (transfer->ssm, bridge_error ("Rust A8 ACK parser failed", status));
      return;
    }

  self->mcu_power_lost = ack.mcu_power_lost != 0;
  fpi_ssm_next_state (transfer->ssm);
}

static gboolean
bootstrap_begin_iap (FpiDeviceGoodix550a *self,
                     FpiSsm              *ssm)
{
  const gchar *resource_path = g_getenv ("GOODIX550A_APP_RESOURCE");
  g_autofree gchar *firmware = NULL;
  g_autoptr(GError) load_error = NULL;
  gsize firmware_length = 0;
  gint status;

  if (!resource_path || resource_path[0] == '\0')
    {
      fpi_ssm_mark_failed (ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                     "GF3258 IAP10007 requires explicit GOODIX550A_APP_RESOURCE for cold-bootstrap validation"));
      return FALSE;
    }

  if (!g_file_get_contents (resource_path, &firmware, &firmware_length, &load_error))
    {
      fpi_ssm_mark_failed (ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                     "failed to read GF3258 APP bootstrap resource: %s",
                                                     load_error->message));
      return FALSE;
    }

  status = goodix550a_bridge_bootstrap_new ((const guint8 *) firmware,
                                             firmware_length,
                                             &self->bootstrap);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      fpi_ssm_mark_failed (ssm,
                           bridge_error ("Rust rejected GF3258 APP bootstrap resource", status));
      return FALSE;
    }

  self->bootstrap_pre_reset_complete = FALSE;
  self->bootstrap_old_usb_invalid = FALSE;
  self->bootstrap_f0_chunks_sent = 0;
  self->bootstrap_firmware_check_result = 0;

  fp_info ("starting explicitly authorized Rust-core IAP bootstrap using %zu-byte APP resource",
           firmware_length);
  bootstrap_schedule_next (self);
  return TRUE;
}

static void
probe_postboot_reset_ack_cb (FpiUsbTransfer *transfer,
                             FpDevice       *device,
                             gpointer        user_data,
                             GError         *error)
{
  Goodix550aBridgeAck ack = { 0 };
  gint status;

  (void) device;
  (void) user_data;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  status = goodix550a_bridge_parse_postboot_reset_ack (transfer->buffer,
                                                        transfer->actual_length,
                                                        &ack);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           bridge_error ("Rust post-bootstrap A2 ACK parser failed", status));
      return;
    }

  fp_dbg ("Rust post-bootstrap A2 ACK: flags=0x%02x mcu_power_lost=%s",
          ack.flags,
          ack.mcu_power_lost ? "true" : "false");
  fpi_ssm_next_state (transfer->ssm);
}

static void
probe_postboot_reset_completion_cb (FpiUsbTransfer *transfer,
                                    FpDevice       *device,
                                    gpointer        user_data,
                                    GError         *error)
{
  guint32 delay_ms;
  gint status;

  (void) device;
  (void) user_data;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  status = goodix550a_bridge_parse_postboot_reset_response (transfer->buffer,
                                                             transfer->actual_length);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           bridge_error ("Rust post-bootstrap A2 completion parser failed", status));
      return;
    }

  delay_ms = goodix550a_bridge_postboot_reset_delay_ms ();
  if (delay_ms > G_MAXINT)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           protocol_error ("Rust post-bootstrap reset delay exceeds libfprint SSM range"));
      return;
    }

  fp_dbg ("GF3258 post-bootstrap reset complete; delaying %u ms before chip-ID read",
          delay_ms);
  fpi_ssm_next_state_delayed (transfer->ssm, (gint) delay_ms);
}

static void
probe_postboot_chip_id_ack_cb (FpiUsbTransfer *transfer,
                               FpDevice       *device,
                               gpointer        user_data,
                               GError         *error)
{
  Goodix550aBridgeAck ack = { 0 };
  gint status;

  (void) device;
  (void) user_data;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  status = goodix550a_bridge_parse_chip_id_ack (transfer->buffer,
                                                 transfer->actual_length,
                                                 &ack);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           bridge_error ("Rust chip-ID ACK parser failed", status));
      return;
    }

  fp_dbg ("Rust chip-ID ACK: flags=0x%02x mcu_power_lost=%s",
          ack.flags,
          ack.mcu_power_lost ? "true" : "false");
  fpi_ssm_next_state (transfer->ssm);
}

static void
probe_postboot_chip_id_completion_cb (FpiUsbTransfer *transfer,
                                      FpDevice       *device,
                                      gpointer        user_data,
                                      GError         *error)
{
  guint32 chip_id = 0;
  gint status;

  (void) device;
  (void) user_data;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  status = goodix550a_bridge_validate_chip_id_response (transfer->buffer,
                                                         transfer->actual_length,
                                                         &chip_id);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           bridge_error ("Rust chip-ID validator failed", status));
      return;
    }

  fp_info ("GF3258 post-bootstrap qualification complete: chip_id=0x%08x",
           (guint) chip_id);
  fpi_ssm_mark_completed (transfer->ssm);
}

static void
probe_version_cb (FpiUsbTransfer *transfer,
                  FpDevice       *device,
                  gpointer        user_data,
                  GError         *error)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  Goodix550aBridgeFirmware firmware = GOODIX550A_BRIDGE_FIRMWARE_UNKNOWN;
  gint status;

  (void) user_data;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  status = goodix550a_bridge_parse_get_version_response (transfer->buffer,
                                                          transfer->actual_length,
                                                          &firmware);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           bridge_error ("Rust probe A8 completion parser failed", status));
      return;
    }

  self->firmware = firmware;
  fp_info ("Rust-core probe A8: firmware=%s mcu_power_lost=%s",
           goodix550a_bridge_firmware_name (self->firmware),
           self->mcu_power_lost ? "true" : "false");

  if (self->firmware == GOODIX550A_BRIDGE_FIRMWARE_IAP10007)
    {
      bootstrap_begin_iap (self, transfer->ssm);
      return;
    }

  if (self->firmware != GOODIX550A_BRIDGE_FIRMWARE_APP15045)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                     "GF3258 probe encountered unsupported firmware"));
      return;
    }

  self->post_bootstrap_handoff = bootstrap_handoff_take (device);
  fp_info ("GF3258 APP probe post-bootstrap handoff=%s",
           self->post_bootstrap_handoff ? "true" : "false");

  if (!self->post_bootstrap_handoff)
    {
      fpi_ssm_mark_completed (transfer->ssm);
      return;
    }

  fp_info ("starting GF3258 post-bootstrap qualification");
  fpi_ssm_next_state (transfer->ssm);
}

static void
probe_run_state (FpiSsm *ssm, FpDevice *device)
{
  FpiUsbTransfer *transfer;
  gint status;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case PROBE_SEND_VERSION:
      transfer = fpi_usb_transfer_new (device);
      fpi_usb_transfer_fill_bulk (transfer, GOODIX550A_EP_OUT, GOODIX550A_USB_BLOCK_SIZE);
      status = goodix550a_bridge_build_get_version_request (transfer->buffer,
                                                             transfer->length);
      if (status != GOODIX550A_BRIDGE_OK)
        {
          fpi_usb_transfer_unref (transfer);
          fpi_ssm_mark_failed (ssm, bridge_error ("Rust probe A8 request builder failed", status));
          return;
        }

      transfer->ssm = ssm;
      fpi_usb_transfer_set_short_error (transfer, TRUE);
      fpi_usb_transfer_submit (transfer,
                               GOODIX550A_TIMEOUT_MS,
                               fpi_device_get_cancellable (device),
                               fpi_ssm_usb_transfer_cb,
                               NULL);
      break;

    case PROBE_READ_ACK:
      transfer = fpi_usb_transfer_new (device);
      fpi_usb_transfer_fill_bulk (transfer, GOODIX550A_EP_IN, GOODIX550A_USB_BLOCK_SIZE);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer,
                               GOODIX550A_TIMEOUT_MS,
                               fpi_device_get_cancellable (device),
                               open_ack_cb,
                               NULL);
      break;

    case PROBE_READ_VERSION:
      transfer = fpi_usb_transfer_new (device);
      fpi_usb_transfer_fill_bulk (transfer, GOODIX550A_EP_IN, GOODIX550A_USB_BLOCK_SIZE);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer,
                               GOODIX550A_TIMEOUT_MS,
                               fpi_device_get_cancellable (device),
                               probe_version_cb,
                               NULL);
      break;

    case PROBE_POSTBOOT_RESET_WRITE:
      transfer = fpi_usb_transfer_new (device);
      fpi_usb_transfer_fill_bulk (transfer, GOODIX550A_EP_OUT, GOODIX550A_USB_BLOCK_SIZE);
      status = goodix550a_bridge_build_postboot_reset_request (transfer->buffer,
                                                                transfer->length);
      if (status != GOODIX550A_BRIDGE_OK)
        {
          fpi_usb_transfer_unref (transfer);
          fpi_ssm_mark_failed (ssm,
                               bridge_error ("Rust post-bootstrap A2 request builder failed", status));
          return;
        }

      transfer->ssm = ssm;
      fpi_usb_transfer_set_short_error (transfer, TRUE);
      fpi_usb_transfer_submit (transfer,
                               GOODIX550A_TIMEOUT_MS,
                               fpi_device_get_cancellable (device),
                               fpi_ssm_usb_transfer_cb,
                               NULL);
      break;

    case PROBE_POSTBOOT_RESET_ACK:
      transfer = fpi_usb_transfer_new (device);
      fpi_usb_transfer_fill_bulk (transfer, GOODIX550A_EP_IN, GOODIX550A_USB_BLOCK_SIZE);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer,
                               GOODIX550A_TIMEOUT_MS,
                               fpi_device_get_cancellable (device),
                               probe_postboot_reset_ack_cb,
                               NULL);
      break;

    case PROBE_POSTBOOT_RESET_COMPLETION:
      transfer = fpi_usb_transfer_new (device);
      fpi_usb_transfer_fill_bulk (transfer, GOODIX550A_EP_IN, GOODIX550A_USB_BLOCK_SIZE);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer,
                               GOODIX550A_TIMEOUT_MS,
                               fpi_device_get_cancellable (device),
                               probe_postboot_reset_completion_cb,
                               NULL);
      break;

    case PROBE_POSTBOOT_CHIP_ID_WRITE:
      transfer = fpi_usb_transfer_new (device);
      fpi_usb_transfer_fill_bulk (transfer, GOODIX550A_EP_OUT, GOODIX550A_USB_BLOCK_SIZE);
      status = goodix550a_bridge_build_chip_id_request (transfer->buffer,
                                                         transfer->length);
      if (status != GOODIX550A_BRIDGE_OK)
        {
          fpi_usb_transfer_unref (transfer);
          fpi_ssm_mark_failed (ssm,
                               bridge_error ("Rust chip-ID request builder failed", status));
          return;
        }

      transfer->ssm = ssm;
      fpi_usb_transfer_set_short_error (transfer, TRUE);
      fpi_usb_transfer_submit (transfer,
                               GOODIX550A_TIMEOUT_MS,
                               fpi_device_get_cancellable (device),
                               fpi_ssm_usb_transfer_cb,
                               NULL);
      break;

    case PROBE_POSTBOOT_CHIP_ID_ACK:
      transfer = fpi_usb_transfer_new (device);
      fpi_usb_transfer_fill_bulk (transfer, GOODIX550A_EP_IN, GOODIX550A_USB_BLOCK_SIZE);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer,
                               GOODIX550A_TIMEOUT_MS,
                               fpi_device_get_cancellable (device),
                               probe_postboot_chip_id_ack_cb,
                               NULL);
      break;

    case PROBE_POSTBOOT_CHIP_ID_COMPLETION:
      transfer = fpi_usb_transfer_new (device);
      fpi_usb_transfer_fill_bulk (transfer, GOODIX550A_EP_IN, GOODIX550A_USB_BLOCK_SIZE);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer,
                               GOODIX550A_TIMEOUT_MS,
                               fpi_device_get_cancellable (device),
                               probe_postboot_chip_id_completion_cb,
                               NULL);
      break;

    default:
      fpi_ssm_mark_failed (ssm, protocol_error ("invalid Goodix probe state"));
      break;
    }
}

static void
open_version_cb (FpiUsbTransfer *transfer,
                 FpDevice       *device,
                 gpointer        user_data,
                 GError         *error)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  Goodix550aBridgeFirmware firmware = GOODIX550A_BRIDGE_FIRMWARE_UNKNOWN;
  gint status;

  (void) user_data;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  status = goodix550a_bridge_parse_get_version_response (transfer->buffer,
                                                          transfer->actual_length,
                                                          &firmware);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      fpi_ssm_mark_failed (transfer->ssm, bridge_error ("Rust A8 completion parser failed", status));
      return;
    }

  self->firmware = firmware;
  fp_info ("Rust-core A8 probe: firmware=%s mcu_power_lost=%s",
           goodix550a_bridge_firmware_name (self->firmware),
           self->mcu_power_lost ? "true" : "false");

  if (self->firmware == GOODIX550A_BRIDGE_FIRMWARE_IAP10007)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                     "GF3258 IAP10007 reached open after probe; cold bootstrap is probe-owned"));
      return;
    }

  if (self->firmware != GOODIX550A_BRIDGE_FIRMWARE_APP15045)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                     "GF3258 libfprint startup encountered unsupported firmware"));
      return;
    }

  if (!self->mcu_power_lost)
    {
      fpi_ssm_mark_completed (transfer->ssm);
      return;
    }

  status = goodix550a_bridge_recovery_new (&self->recovery);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      fpi_ssm_mark_failed (transfer->ssm, bridge_error ("Rust ChicagoH engine creation failed", status));
      return;
    }

  recovery_schedule_next (self);
}

static void
open_run_state (FpiSsm *ssm, FpDevice *device)
{
  FpiUsbTransfer *transfer;
  gint status;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_SEND_VERSION:
      transfer = fpi_usb_transfer_new (device);
      fpi_usb_transfer_fill_bulk (transfer, GOODIX550A_EP_OUT, GOODIX550A_USB_BLOCK_SIZE);
      status = goodix550a_bridge_build_get_version_request (transfer->buffer,
                                                            GOODIX550A_USB_BLOCK_SIZE);
      if (status != GOODIX550A_BRIDGE_OK)
        {
          fpi_usb_transfer_unref (transfer);
          fpi_ssm_mark_failed (ssm, bridge_error ("Rust A8 request builder failed", status));
          return;
        }
      transfer->ssm = ssm;
      transfer->short_is_error = TRUE;
      fpi_usb_transfer_submit (transfer,
                               GOODIX550A_TIMEOUT_MS,
                               fpi_device_get_cancellable (device),
                               fpi_ssm_usb_transfer_cb,
                               NULL);
      break;

    case OPEN_READ_ACK:
      transfer = fpi_usb_transfer_new (device);
      fpi_usb_transfer_fill_bulk (transfer, GOODIX550A_EP_IN, GOODIX550A_USB_BLOCK_SIZE);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer,
                               GOODIX550A_TIMEOUT_MS,
                               fpi_device_get_cancellable (device),
                               open_ack_cb,
                               NULL);
      break;

    case OPEN_READ_VERSION:
      transfer = fpi_usb_transfer_new (device);
      fpi_usb_transfer_fill_bulk (transfer, GOODIX550A_EP_IN, GOODIX550A_USB_BLOCK_SIZE);
      transfer->ssm = ssm;
      fpi_usb_transfer_submit (transfer,
                               GOODIX550A_TIMEOUT_MS,
                               fpi_device_get_cancellable (device),
                               open_version_cb,
                               NULL);
      break;

    default:
      fpi_ssm_mark_failed (ssm, protocol_error ("invalid Goodix open state"));
      break;
    }
}

static void
release_claim_after_failed_open (FpiDeviceGoodix550a *self)
{
  g_autoptr(GError) release_error = NULL;

  if (!self->claimed)
    return;

  if (!g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (self)),
                                       GOODIX550A_INTERFACE,
                                       0,
                                       &release_error))
    fp_warn ("failed to release interface after open error: %s", release_error->message);

  self->claimed = FALSE;
}

static void
open_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);

  (void) ssm;
  self->open_ssm = NULL;

  if (error)
    {
      recovery_clear (self);
      release_claim_after_failed_open (self);
    }

  fpi_device_open_complete (device, error);
}

static void
capture_clear (FpiDeviceGoodix550a *self)
{
  if (!self->capture)
    return;

  goodix550a_bridge_capture_free (self->capture);
  self->capture = NULL;
}

static void
capture_fail (FpiDeviceGoodix550a *self, GError *error)
{
  capture_clear (self);
  fpi_device_capture_complete (FP_DEVICE (self), NULL, error);
}

static void
capture_finish_success (FpiDeviceGoodix550a *self)
{
  Goodix550aBridgeCaptureInfo info = { 0 };
  FpImage *image;
  gint status;

  image = fp_image_new (GOODIX550A_IMAGE_WIDTH, GOODIX550A_IMAGE_HEIGHT);
  status = goodix550a_bridge_capture_copy_image_u8 (self->capture,
                                                     image->data,
                                                     GOODIX550A_IMAGE_PIXELS,
                                                     &info);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      GError *error = capture_bridge_error (self, "Rust capture result failed", status);
      g_object_unref (image);
      capture_fail (self, error);
      return;
    }

  if (info.pixel_count != GOODIX550A_IMAGE_PIXELS)
    {
      GError *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                "Rust capture returned %zu pixels, expected %zu",
                                                info.pixel_count,
                                                (gsize) GOODIX550A_IMAGE_PIXELS);
      g_object_unref (image);
      capture_fail (self, error);
      return;
    }

  fp_info ("Rust-core capture: protected=%zuB crc=0x%08x pixels=%zu",
           info.protected_bytes,
           info.stored_crc,
           info.pixel_count);

  capture_clear (self);
  fpi_device_capture_complete (FP_DEVICE (self), image, NULL);
}

static void
capture_transfer_cb (FpiUsbTransfer *transfer,
                     FpDevice       *device,
                     gpointer        user_data,
                     GError         *error)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  Goodix550aBridgeTransferDirection direction =
    (Goodix550aBridgeTransferDirection) GPOINTER_TO_UINT (user_data);
  const guint8 *input = NULL;
  gsize input_length = 0;
  guint8 advanced = 0;
  gint status;

  if (error)
    {
      capture_fail (self, error);
      return;
    }

  if (direction == GOODIX550A_BRIDGE_TRANSFER_IN)
    {
      input = transfer->buffer;
      input_length = transfer->actual_length;
    }

  status = goodix550a_bridge_capture_complete_transfer (self->capture,
                                                         input,
                                                         input_length,
                                                         &advanced);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      capture_fail (self, capture_bridge_error (self, "Rust capture transfer parser failed", status));
      return;
    }

  if (!advanced)
    fp_dbg ("Rust capture ignored unrelated IN packet; repeating stage");

  capture_schedule_next (self);
}

static void
capture_schedule_next (FpiDeviceGoodix550a *self)
{
  Goodix550aBridgeCaptureAction action = { 0 };
  guint8 output[GOODIX550A_USB_BLOCK_SIZE] = { 0 };
  FpiUsbTransfer *transfer;
  gint status;

  status = goodix550a_bridge_capture_next_action (self->capture,
                                                   &action,
                                                   output,
                                                   sizeof (output));
  if (status != GOODIX550A_BRIDGE_OK)
    {
      capture_fail (self, capture_bridge_error (self, "Rust capture action failed", status));
      return;
    }

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_COMPLETE)
    {
      capture_finish_success (self);
      return;
    }

  if (action.direction != GOODIX550A_BRIDGE_TRANSFER_OUT &&
      action.direction != GOODIX550A_BRIDGE_TRANSFER_IN)
    {
      capture_fail (self, protocol_error ("Rust capture returned an invalid transfer direction"));
      return;
    }

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT &&
      action.transfer_length > sizeof (output))
    {
      capture_fail (self, protocol_error ("Rust capture OUT action exceeds the bridge scratch buffer"));
      return;
    }

  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk (transfer, action.endpoint, action.transfer_length);

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT)
    memcpy (transfer->buffer, output, action.transfer_length);

  fpi_usb_transfer_set_short_error (transfer, action.short_is_error != 0);
  fp_dbg ("Rust capture stage=%u direction=%s endpoint=0x%02x length=%zu timeout=%u",
          action.stage,
          action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT ? "OUT" : "IN",
          (guint) action.endpoint,
          action.transfer_length,
          action.timeout_ms);

  fpi_usb_transfer_submit (transfer,
                           action.timeout_ms,
                           fpi_device_get_cancellable (FP_DEVICE (self)),
                           capture_transfer_cb,
                           GUINT_TO_POINTER (action.direction));
}

static const gchar *
enrollment_disposition_name (guint32 disposition)
{
  switch (disposition)
    {
    case GOODIX550A_BRIDGE_ENROLL_RETRY:
      return "RETRY";
    case GOODIX550A_BRIDGE_ENROLL_PROGRESS:
      return "PROGRESS";
    case GOODIX550A_BRIDGE_ENROLL_COMPLETE:
      return "COMPLETE";
    default:
      return "INVALID";
    }
}

static void
enrollment_clear (FpiDeviceGoodix550a *self)
{
  if (!self->enrollment)
    return;

  goodix550a_bridge_enrollment_free (self->enrollment);
  self->enrollment = NULL;
}

static void
enrollment_fail (FpiDeviceGoodix550a *self,
                 GError              *error)
{
  enrollment_clear (self);
  fpi_device_enroll_complete (FP_DEVICE (self), NULL, error);
}

static gboolean
enrollment_start_next_touch (FpiDeviceGoodix550a *self)
{
  gint status = goodix550a_bridge_enrollment_start_next_touch (self->enrollment);

  if (status != GOODIX550A_BRIDGE_OK)
    {
      enrollment_fail (self,
                       enrollment_bridge_error (self,
                                                "Rust enrollment next-touch setup failed",
                                                status));
      return FALSE;
    }

  enrollment_schedule_next (self);
  return TRUE;
}

static void
enrollment_finish_touch (FpiDeviceGoodix550a *self)
{
  Goodix550aBridgeEnrollmentInfo info = { 0 };
  gint status;

  status = goodix550a_bridge_enrollment_result (self->enrollment, &info);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      enrollment_fail (self,
                       enrollment_bridge_error (self,
                                                "Rust enrollment result failed",
                                                status));
      return;
    }

  if (info.disposition != GOODIX550A_BRIDGE_ENROLL_RETRY &&
      info.disposition != GOODIX550A_BRIDGE_ENROLL_PROGRESS &&
      info.disposition != GOODIX550A_BRIDGE_ENROLL_COMPLETE)
    {
      enrollment_fail (self, protocol_error ("Rust enrollment returned an invalid disposition"));
      return;
    }

  if (info.sample_count > GOODIX550A_ENROLL_STAGES ||
      info.progress_percent > 100 ||
      info.pixel_count != GOODIX550A_IMAGE_PIXELS)
    {
      enrollment_fail (self, protocol_error ("Rust enrollment returned invalid progress metadata"));
      return;
    }

  fp_info ("Rust-core enrollment: disposition=%s sample=%zu/%d progress=%zu protected=%zuB crc=0x%08x pixels=%zu tgla=%zuB",
           enrollment_disposition_name (info.disposition),
           info.sample_count,
           GOODIX550A_ENROLL_STAGES,
           info.progress_percent,
           info.protected_bytes,
           info.stored_crc,
           info.pixel_count,
           info.tgla_bytes);

  if (info.disposition == GOODIX550A_BRIDGE_ENROLL_RETRY)
    {
      fpi_device_enroll_progress (FP_DEVICE (self),
                                  info.sample_count,
                                  NULL,
                                  fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
      enrollment_start_next_touch (self);
      return;
    }

  if (info.disposition == GOODIX550A_BRIDGE_ENROLL_PROGRESS)
    {
      fpi_device_enroll_progress (FP_DEVICE (self), info.sample_count, NULL, NULL);
      enrollment_start_next_touch (self);
      return;
    }

  if (info.sample_count != GOODIX550A_ENROLL_STAGES ||
      info.progress_percent != 100 ||
      info.tgla_bytes == 0)
    {
      enrollment_fail (self, protocol_error ("Rust completed enrollment without a full TGLA gallery"));
      return;
    }

  {
    FpPrint *print = NULL;
    g_autofree guint8 *tgla = g_malloc (info.tgla_bytes);
    g_autoptr(GVariant) tgla_variant = NULL;
    g_autoptr(GVariant) print_data = NULL;
    size_t written = 0;

    status = goodix550a_bridge_enrollment_copy_tgla (self->enrollment,
                                                      tgla,
                                                      info.tgla_bytes,
                                                      &written);
    if (status != GOODIX550A_BRIDGE_OK)
      {
        enrollment_fail (self,
                         enrollment_bridge_error (self,
                                                  "Rust enrollment TGLA copy failed",
                                                  status));
        return;
      }

    if (written != info.tgla_bytes)
      {
        enrollment_fail (self, protocol_error ("Rust enrollment TGLA length changed during copy"));
        return;
      }

    fpi_device_get_enroll_data (FP_DEVICE (self), &print);
    if (!print)
      {
        enrollment_fail (self, protocol_error ("libfprint enrollment template disappeared"));
        return;
      }

    tgla_variant = g_variant_ref_sink (g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                                                  tgla,
                                                                  written,
                                                                  sizeof (guint8)));
    print_data = g_variant_ref_sink (g_variant_new ("(u@ay)",
                                                    GOODIX550A_PRINT_VERSION,
                                                    g_variant_ref (tgla_variant)));
    g_object_set (print, "fpi-data", print_data, NULL);

    fp_info ("Rust-core enrollment TGLA ready: samples=%zu tgla=%zuB",
             info.sample_count,
             written);

    fpi_device_enroll_progress (FP_DEVICE (self), info.sample_count, NULL, NULL);
    enrollment_clear (self);
    fpi_device_enroll_complete (FP_DEVICE (self), g_object_ref (print), NULL);
  }
}

static void
enrollment_transfer_cb (FpiUsbTransfer *transfer,
                        FpDevice       *device,
                        gpointer        user_data,
                        GError         *error)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  Goodix550aBridgeTransferDirection direction =
    (Goodix550aBridgeTransferDirection) GPOINTER_TO_UINT (user_data);
  const guint8 *input = NULL;
  gsize input_length = 0;
  guint8 advanced = 0;
  gint status;

  if (error)
    {
      enrollment_fail (self, error);
      return;
    }

  if (direction == GOODIX550A_BRIDGE_TRANSFER_IN)
    {
      input = transfer->buffer;
      input_length = transfer->actual_length;
    }

  status = goodix550a_bridge_enrollment_complete_transfer (self->enrollment,
                                                            input,
                                                            input_length,
                                                            &advanced);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      enrollment_fail (self,
                       enrollment_bridge_error (self,
                                                "Rust enrollment transfer parser failed",
                                                status));
      return;
    }

  if (!advanced)
    fp_dbg ("Rust enrollment ignored unrelated IN packet; repeating stage");

  enrollment_schedule_next (self);
}

static void
enrollment_schedule_next (FpiDeviceGoodix550a *self)
{
  Goodix550aBridgeEnrollmentAction action = { 0 };
  guint8 output[GOODIX550A_USB_BLOCK_SIZE] = { 0 };
  FpiUsbTransfer *transfer;
  gint status;

  status = goodix550a_bridge_enrollment_next_action (self->enrollment,
                                                      &action,
                                                      output,
                                                      sizeof (output));
  if (status != GOODIX550A_BRIDGE_OK)
    {
      enrollment_fail (self,
                       enrollment_bridge_error (self,
                                                "Rust enrollment action failed",
                                                status));
      return;
    }

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_COMPLETE)
    {
      enrollment_finish_touch (self);
      return;
    }

  if (action.direction != GOODIX550A_BRIDGE_TRANSFER_OUT &&
      action.direction != GOODIX550A_BRIDGE_TRANSFER_IN)
    {
      enrollment_fail (self,
                       protocol_error ("Rust enrollment returned an invalid transfer direction"));
      return;
    }

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT &&
      action.transfer_length > sizeof (output))
    {
      enrollment_fail (self,
                       protocol_error ("Rust enrollment OUT action exceeds the bridge scratch buffer"));
      return;
    }

  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk (transfer, action.endpoint, action.transfer_length);

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT)
    memcpy (transfer->buffer, output, action.transfer_length);

  fpi_usb_transfer_set_short_error (transfer, action.short_is_error != 0);
  fp_dbg ("Rust enroll stage=%u direction=%s endpoint=0x%02x length=%zu timeout=%u",
          action.stage,
          action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT ? "OUT" : "IN",
          (guint) action.endpoint,
          action.transfer_length,
          action.timeout_ms);

  fpi_usb_transfer_submit (transfer,
                           action.timeout_ms,
                           fpi_device_get_cancellable (FP_DEVICE (self)),
                           enrollment_transfer_cb,
                           GUINT_TO_POINTER (action.direction));
}

static const gchar *
verification_disposition_name (guint32 disposition)
{
  switch (disposition)
    {
    case GOODIX550A_BRIDGE_VERIFY_RETRY:
      return "RETRY";
    case GOODIX550A_BRIDGE_VERIFY_MATCH:
      return "MATCH";
    case GOODIX550A_BRIDGE_VERIFY_NO_MATCH:
      return "NO_MATCH";
    default:
      return "INVALID";
    }
}

static void
verification_clear (FpiDeviceGoodix550a *self)
{
  if (!self->verification)
    return;

  goodix550a_bridge_verification_free (self->verification);
  self->verification = NULL;
}

static void
verification_fail (FpiDeviceGoodix550a *self,
                   GError              *error)
{
  verification_clear (self);
  fpi_device_verify_complete (FP_DEVICE (self), error);
}

static void
verification_finish_success (FpiDeviceGoodix550a *self)
{
  Goodix550aBridgeVerificationInfo info = { 0 };
  gint status;

  status = goodix550a_bridge_verification_result (self->verification, &info);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      verification_fail (self,
                         verification_bridge_error (self,
                                                    "Rust verification result failed",
                                                    status));
      return;
    }

  if (info.disposition != GOODIX550A_BRIDGE_VERIFY_RETRY &&
      info.disposition != GOODIX550A_BRIDGE_VERIFY_MATCH &&
      info.disposition != GOODIX550A_BRIDGE_VERIFY_NO_MATCH)
    {
      verification_fail (self,
                         protocol_error ("Rust verification returned an invalid disposition"));
      return;
    }

  fp_info ("Rust-core verification: disposition=%s score=%d protected=%zuB crc=0x%08x pixels=%zu",
           verification_disposition_name (info.disposition),
           info.score,
           info.protected_bytes,
           info.stored_crc,
           info.pixel_count);

  verification_clear (self);

  switch (info.disposition)
    {
    case GOODIX550A_BRIDGE_VERIFY_RETRY:
      fpi_device_verify_report (FP_DEVICE (self),
                                FPI_MATCH_ERROR,
                                NULL,
                                fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
      break;
    case GOODIX550A_BRIDGE_VERIFY_MATCH:
      fpi_device_verify_report (FP_DEVICE (self), FPI_MATCH_SUCCESS, NULL, NULL);
      break;
    case GOODIX550A_BRIDGE_VERIFY_NO_MATCH:
      fpi_device_verify_report (FP_DEVICE (self), FPI_MATCH_FAIL, NULL, NULL);
      break;
    default:
      g_assert_not_reached ();
    }

  fpi_device_verify_complete (FP_DEVICE (self), NULL);
}

static void
verification_transfer_cb (FpiUsbTransfer *transfer,
                          FpDevice       *device,
                          gpointer        user_data,
                          GError         *error)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  Goodix550aBridgeTransferDirection direction =
    (Goodix550aBridgeTransferDirection) GPOINTER_TO_UINT (user_data);
  const guint8 *input = NULL;
  gsize input_length = 0;
  guint8 advanced = 0;
  gint status;

  if (error)
    {
      verification_fail (self, error);
      return;
    }

  if (direction == GOODIX550A_BRIDGE_TRANSFER_IN)
    {
      input = transfer->buffer;
      input_length = transfer->actual_length;
    }

  status = goodix550a_bridge_verification_complete_transfer (self->verification,
                                                              input,
                                                              input_length,
                                                              &advanced);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      verification_fail (self,
                         verification_bridge_error (self,
                                                    "Rust verification transfer parser failed",
                                                    status));
      return;
    }

  if (!advanced)
    fp_dbg ("Rust verification ignored unrelated IN packet; repeating stage");

  verification_schedule_next (self);
}

static void
verification_schedule_next (FpiDeviceGoodix550a *self)
{
  Goodix550aBridgeVerificationAction action = { 0 };
  guint8 output[GOODIX550A_USB_BLOCK_SIZE] = { 0 };
  FpiUsbTransfer *transfer;
  gint status;

  status = goodix550a_bridge_verification_next_action (self->verification,
                                                        &action,
                                                        output,
                                                        sizeof (output));
  if (status != GOODIX550A_BRIDGE_OK)
    {
      verification_fail (self,
                         verification_bridge_error (self,
                                                    "Rust verification action failed",
                                                    status));
      return;
    }

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_COMPLETE)
    {
      verification_finish_success (self);
      return;
    }

  if (action.direction != GOODIX550A_BRIDGE_TRANSFER_OUT &&
      action.direction != GOODIX550A_BRIDGE_TRANSFER_IN)
    {
      verification_fail (self,
                         protocol_error ("Rust verification returned an invalid transfer direction"));
      return;
    }

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT &&
      action.transfer_length > sizeof (output))
    {
      verification_fail (self,
                         protocol_error ("Rust verification OUT action exceeds the bridge scratch buffer"));
      return;
    }

  transfer = fpi_usb_transfer_new (FP_DEVICE (self));
  fpi_usb_transfer_fill_bulk (transfer, action.endpoint, action.transfer_length);

  if (action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT)
    memcpy (transfer->buffer, output, action.transfer_length);

  fpi_usb_transfer_set_short_error (transfer, action.short_is_error != 0);
  fp_dbg ("Rust verify stage=%u direction=%s endpoint=0x%02x length=%zu timeout=%u",
          action.stage,
          action.direction == GOODIX550A_BRIDGE_TRANSFER_OUT ? "OUT" : "IN",
          (guint) action.endpoint,
          action.transfer_length,
          action.timeout_ms);

  fpi_usb_transfer_submit (transfer,
                           action.timeout_ms,
                           fpi_device_get_cancellable (FP_DEVICE (self)),
                           verification_transfer_cb,
                           GUINT_TO_POINTER (action.direction));
}

static void
probe_release_and_close (FpiDeviceGoodix550a *self)
{
  g_autoptr(GError) release_error = NULL;
  g_autoptr(GError) close_error = NULL;
  GUsbDevice *usb_device = fpi_device_get_usb_device (FP_DEVICE (self));

  if (self->claimed)
    {
      if (!g_usb_device_release_interface (usb_device,
                                           GOODIX550A_INTERFACE,
                                           0,
                                           &release_error))
        fp_dbg ("failed to release GF3258 interface after probe: %s",
                release_error->message);

      self->claimed = FALSE;
    }

  if (!g_usb_device_close (usb_device, &close_error))
    fp_dbg ("failed to close GF3258 USB device after probe: %s",
            close_error->message);
}

static void
probe_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);

  (void) ssm;
  self->probe_ssm = NULL;

  bootstrap_clear (self);
  probe_release_and_close (self);

  fpi_device_probe_complete (device, NULL, NULL, error);
}

static void
dev_probe (FpDevice *device)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  GUsbDevice *usb_device = fpi_device_get_usb_device (device);
  g_autoptr(GError) error = NULL;

  if (!g_usb_device_open (usb_device, &error))
    {
      fpi_device_probe_complete (device, NULL, NULL, g_steal_pointer (&error));
      return;
    }

  if (!g_usb_device_claim_interface (usb_device,
                                     GOODIX550A_INTERFACE,
                                     0,
                                     &error))
    {
      g_usb_device_close (usb_device, NULL);
      fpi_device_probe_complete (device, NULL, NULL, g_steal_pointer (&error));
      return;
    }

  self->claimed = TRUE;
  self->mcu_power_lost = FALSE;
  self->firmware = GOODIX550A_BRIDGE_FIRMWARE_UNKNOWN;
  self->bootstrap_old_usb_invalid = FALSE;
  self->post_bootstrap_handoff = FALSE;
  self->probe_ssm = fpi_ssm_new (device, probe_run_state, PROBE_NUM_STATES);
  fpi_ssm_start (self->probe_ssm, probe_done);
}

static void
dev_open (FpDevice *device)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  g_autoptr(GError) error = NULL;

  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (device),
                                     GOODIX550A_INTERFACE,
                                     0,
                                     &error))
    {
      fpi_device_open_complete (device, g_steal_pointer (&error));
      return;
    }

  self->claimed = TRUE;
  self->mcu_power_lost = FALSE;
  self->firmware = GOODIX550A_BRIDGE_FIRMWARE_UNKNOWN;
  self->bootstrap_old_usb_invalid = FALSE;
  self->open_ssm = fpi_ssm_new (device, open_run_state, OPEN_NUM_STATES);
  fpi_ssm_start (self->open_ssm, open_done);
}

static void
dev_close (FpDevice *device)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  GError *error = NULL;

  bootstrap_clear (self);
  recovery_clear (self);
  capture_clear (self);
  enrollment_clear (self);
  verification_clear (self);

  if (self->claimed)
    {
      g_usb_device_release_interface (fpi_device_get_usb_device (device),
                                      GOODIX550A_INTERFACE,
                                      0,
                                      &error);
      self->claimed = FALSE;
    }

  fpi_device_close_complete (device, error);
}

static void
dev_capture (FpDevice *device)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  gboolean wait_for_finger = FALSE;
  gint status;

  fpi_device_get_capture_data (device, &wait_for_finger);
  if (!wait_for_finger)
    {
      fpi_device_capture_complete (device,
                                   NULL,
                                   fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                             "unconditional GF3258 capture is not implemented"));
      return;
    }

  if (self->firmware != GOODIX550A_BRIDGE_FIRMWARE_APP15045)
    {
      fpi_device_capture_complete (device,
                                   NULL,
                                   fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                             "GF3258 capture requires APP15045"));
      return;
    }

  if (self->mcu_power_lost)
    {
      fpi_device_capture_complete (device,
                                   NULL,
                                   fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                             "GF3258 volatile configuration must be restored before capture"));
      return;
    }

  if (self->capture || self->enrollment || self->verification)
    {
      fpi_device_capture_complete (device,
                                   NULL,
                                   fpi_device_error_new (FP_DEVICE_ERROR_BUSY));
      return;
    }

  status = goodix550a_bridge_capture_new (&self->capture);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      fpi_device_capture_complete (device,
                                   NULL,
                                   bridge_error ("Rust capture engine creation failed", status));
      return;
    }

  capture_schedule_next (self);
}

static void
dev_enroll (FpDevice *device)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  FpPrint *print = NULL;
  FpiPrintType print_type = FPI_PRINT_UNDEFINED;
  gint status;

  if (self->firmware != GOODIX550A_BRIDGE_FIRMWARE_APP15045)
    {
      fpi_device_enroll_complete (device,
                                  NULL,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                            "GF3258 enrollment requires APP15045"));
      return;
    }

  if (self->mcu_power_lost)
    {
      fpi_device_enroll_complete (device,
                                  NULL,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                            "GF3258 volatile configuration must be restored before enrollment"));
      return;
    }

  if (self->enrollment || self->verification || self->capture)
    {
      fpi_device_enroll_complete (device, NULL, fpi_device_error_new (FP_DEVICE_ERROR_BUSY));
      return;
    }

  fpi_device_get_enroll_data (device, &print);
  if (!print)
    {
      fpi_device_enroll_complete (device,
                                  NULL,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                            "GF3258 enrollment template is missing"));
      return;
    }

  g_object_get (print, "fpi-type", &print_type, NULL);
  if (print_type != FPI_PRINT_UNDEFINED)
    {
      fpi_device_enroll_complete (device,
                                  NULL,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                            "GF3258 print updates are not supported"));
      return;
    }

  fpi_print_set_type (print, FPI_PRINT_RAW);

  status = goodix550a_bridge_enrollment_new (&self->enrollment);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      fpi_device_enroll_complete (device,
                                  NULL,
                                  bridge_error ("Rust enrollment engine creation failed", status));
      return;
    }

  fp_info ("Rust-core enrollment started: target=%d", GOODIX550A_ENROLL_STAGES);
  enrollment_schedule_next (self);
}

static void
dev_verify (FpDevice *device)
{
  FpiDeviceGoodix550a *self = FPI_DEVICE_GOODIX550A (device);
  FpPrint *print = NULL;
  g_autoptr(GVariant) print_data = NULL;
  g_autoptr(GVariant) tgla_variant = NULL;
  const guint8 *tgla;
  gsize tgla_length = 0;
  guint32 version = 0;
  gint status;

  if (self->firmware != GOODIX550A_BRIDGE_FIRMWARE_APP15045)
    {
      fpi_device_verify_complete (device,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                            "GF3258 verification requires APP15045"));
      return;
    }

  if (self->mcu_power_lost)
    {
      fpi_device_verify_complete (device,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                            "GF3258 volatile configuration must be restored before verification"));
      return;
    }

  if (self->verification || self->enrollment || self->capture)
    {
      fpi_device_verify_complete (device, fpi_device_error_new (FP_DEVICE_ERROR_BUSY));
      return;
    }

  fpi_device_get_verify_data (device, &print);
  if (!print)
    {
      fpi_device_verify_complete (device,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                            "GF3258 verification print is missing"));
      return;
    }

  g_object_get (print, "fpi-data", &print_data, NULL);
  if (!print_data || !g_variant_is_of_type (print_data, G_VARIANT_TYPE (GOODIX550A_PRINT_TYPE)))
    {
      fpi_device_verify_complete (device,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                            "GF3258 print data is not a versioned TGLA payload"));
      return;
    }

  g_variant_get (print_data, "(u@ay)", &version, &tgla_variant);
  if (version != GOODIX550A_PRINT_VERSION)
    {
      fpi_device_verify_complete (device,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                            "unsupported GF3258 print-data version %u",
                                                            version));
      return;
    }

  tgla = g_variant_get_fixed_array (tgla_variant, &tgla_length, sizeof (guint8));
  if (!tgla || tgla_length == 0)
    {
      fpi_device_verify_complete (device,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                            "GF3258 print contains an empty TGLA payload"));
      return;
    }

  status = goodix550a_bridge_verification_new (tgla, tgla_length, &self->verification);
  if (status != GOODIX550A_BRIDGE_OK)
    {
      fpi_device_verify_complete (device,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                            "Rust rejected GF3258 TGLA before capture: %s",
                                                            goodix550a_bridge_status_message (status)));
      return;
    }

  fp_info ("Rust-core verification template accepted: tgla=%zuB", tgla_length);
  verification_schedule_next (self);
}

static void
dev_cancel (FpDevice *device)
{
  /*
   * Every interactive transfer carries the action GCancellable. Cancellation
   * therefore completes the current FpiUsbTransfer with G_IO_ERROR_CANCELLED;
   * the active capture/enrollment/verification callback terminates its bridge transaction.
   */
  (void) device;
}

static const FpIdEntry id_table[] = {
  { .vid = GOODIX550A_USB_VID, .pid = GOODIX550A_USB_PID, },
  { .vid = 0, .pid = 0, },
};

static void
fpi_device_goodix550a_init (FpiDeviceGoodix550a *self)
{
  self->probe_ssm = NULL;
  self->open_ssm = NULL;
  self->bootstrap = NULL;
  self->recovery = NULL;
  self->capture = NULL;
  self->enrollment = NULL;
  self->verification = NULL;
  self->claimed = FALSE;
  self->mcu_power_lost = FALSE;
  self->firmware = GOODIX550A_BRIDGE_FIRMWARE_UNKNOWN;
  self->bootstrap_pre_reset_complete = FALSE;
  self->bootstrap_old_usb_invalid = FALSE;
  self->post_bootstrap_handoff = FALSE;
  self->bootstrap_f0_chunks_sent = 0;
  self->bootstrap_firmware_check_result = 0;
}

static void
fpi_device_goodix550a_class_init (FpiDeviceGoodix550aClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id = "goodix550a";
  dev_class->full_name = "Goodix GF3258 WN2 Fingerprint Sensor";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->temp_hot_seconds = -1;
  dev_class->nr_enroll_stages = GOODIX550A_ENROLL_STAGES;
  dev_class->probe = dev_probe;
  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->capture = dev_capture;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify;
  dev_class->cancel = dev_cancel;

  fpi_device_class_auto_initialize_features (dev_class);
}
