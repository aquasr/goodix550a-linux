// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum
{
  GOODIX550A_BRIDGE_OK = 0,
  GOODIX550A_BRIDGE_INVALID_ARGUMENT = -1,
  GOODIX550A_BRIDGE_BUFFER_TOO_SMALL = -2,
  GOODIX550A_BRIDGE_PROTOCOL_ERROR = -3,
};

typedef enum
{
  GOODIX550A_BRIDGE_FIRMWARE_UNKNOWN = 0,
  GOODIX550A_BRIDGE_FIRMWARE_APP15045 = 1,
  GOODIX550A_BRIDGE_FIRMWARE_IAP10007 = 2,
} Goodix550aBridgeFirmware;

typedef enum
{
  GOODIX550A_BRIDGE_TRANSFER_COMPLETE = 0,
  GOODIX550A_BRIDGE_TRANSFER_OUT = 1,
  GOODIX550A_BRIDGE_TRANSFER_IN = 2,
} Goodix550aBridgeTransferDirection;

typedef struct
{
  uint8_t flags;
  uint8_t mcu_power_lost;
} Goodix550aBridgeAck;

typedef struct Goodix550aBridgeBootstrap Goodix550aBridgeBootstrap;

typedef struct
{
  uint32_t direction;
  uint32_t stage;
  size_t transfer_length;
  uint32_t timeout_ms;
  uint8_t endpoint;
  uint8_t short_is_error;
  uint16_t reserved;
} Goodix550aBridgeBootstrapAction;

typedef struct
{
  size_t f0_chunks_sent;
  uint32_t firmware_check_result;
} Goodix550aBridgeBootstrapInfo;

typedef struct Goodix550aBridgeRecovery Goodix550aBridgeRecovery;

typedef struct
{
  uint32_t direction;
  uint32_t stage;
  size_t transfer_length;
  uint32_t timeout_ms;
  uint8_t endpoint;
  uint8_t short_is_error;
  uint16_t reserved;
} Goodix550aBridgeRecoveryAction;

typedef struct
{
  uint16_t tcode;
  uint16_t diff;
  uint8_t fdt_offset;
  uint8_t reserved;
  uint16_t checksum;
} Goodix550aBridgeRecoveryInfo;

typedef struct Goodix550aBridgeEnrollment Goodix550aBridgeEnrollment;

typedef enum
{
  GOODIX550A_BRIDGE_ENROLL_RETRY = 1,
  GOODIX550A_BRIDGE_ENROLL_PROGRESS = 2,
  GOODIX550A_BRIDGE_ENROLL_COMPLETE = 3,
} Goodix550aBridgeEnrollmentDisposition;

typedef struct
{
  uint32_t direction;
  uint32_t stage;
  size_t transfer_length;
  uint32_t timeout_ms;
  uint8_t endpoint;
  uint8_t short_is_error;
  uint16_t reserved;
} Goodix550aBridgeEnrollmentAction;

typedef struct
{
  uint32_t disposition;
  size_t sample_count;
  size_t progress_percent;
  size_t protected_bytes;
  size_t pixel_count;
  uint32_t stored_crc;
  size_t tgla_bytes;
} Goodix550aBridgeEnrollmentInfo;

typedef struct Goodix550aBridgeVerification Goodix550aBridgeVerification;

typedef enum
{
  GOODIX550A_BRIDGE_VERIFY_RETRY = 1,
  GOODIX550A_BRIDGE_VERIFY_MATCH = 2,
  GOODIX550A_BRIDGE_VERIFY_NO_MATCH = 3,
} Goodix550aBridgeVerificationDisposition;

typedef struct
{
  uint32_t direction;
  uint32_t stage;
  size_t transfer_length;
  uint32_t timeout_ms;
  uint8_t endpoint;
  uint8_t short_is_error;
  uint16_t reserved;
} Goodix550aBridgeVerificationAction;

typedef struct
{
  uint32_t disposition;
  int32_t score;
  size_t protected_bytes;
  size_t pixel_count;
  uint32_t stored_crc;
} Goodix550aBridgeVerificationInfo;

typedef struct Goodix550aBridgeCapture Goodix550aBridgeCapture;

typedef struct
{
  uint32_t direction;
  uint32_t stage;
  size_t transfer_length;
  uint32_t timeout_ms;
  uint8_t endpoint;
  uint8_t short_is_error;
  uint16_t reserved;
} Goodix550aBridgeCaptureAction;

typedef struct
{
  size_t protected_bytes;
  size_t pixel_count;
  uint32_t stored_crc;
} Goodix550aBridgeCaptureInfo;

int goodix550a_bridge_build_postboot_reset_request (uint8_t *output,
                                                      size_t   output_length);

int goodix550a_bridge_parse_postboot_reset_ack (const uint8_t       *input,
                                                 size_t               input_length,
                                                 Goodix550aBridgeAck *ack);

int goodix550a_bridge_parse_postboot_reset_response (const uint8_t *input,
                                                      size_t         input_length);

uint32_t goodix550a_bridge_postboot_reset_delay_ms (void);

int goodix550a_bridge_build_chip_id_request (uint8_t *output,
                                              size_t   output_length);

int goodix550a_bridge_parse_chip_id_ack (const uint8_t       *input,
                                          size_t               input_length,
                                          Goodix550aBridgeAck *ack);

int goodix550a_bridge_validate_chip_id_response (const uint8_t *input,
                                                  size_t         input_length,
                                                  uint32_t      *chip_id);

int goodix550a_bridge_build_bootstrap_reset_request (uint8_t *output,
                                                       size_t   output_length);

int goodix550a_bridge_parse_bootstrap_reset_ack (const uint8_t       *input,
                                                  size_t               input_length,
                                                  Goodix550aBridgeAck *ack);

int goodix550a_bridge_build_get_version_request (uint8_t *output,
                                                  size_t   output_length);

int goodix550a_bridge_parse_get_version_ack (const uint8_t       *input,
                                              size_t               input_length,
                                              Goodix550aBridgeAck *ack);

int goodix550a_bridge_parse_get_version_response (const uint8_t             *input,
                                                   size_t                     input_length,
                                                   Goodix550aBridgeFirmware *firmware);

int goodix550a_bridge_bootstrap_new (const uint8_t            *firmware,
                                      size_t                    firmware_length,
                                      Goodix550aBridgeBootstrap **bootstrap);
void goodix550a_bridge_bootstrap_free (Goodix550aBridgeBootstrap *bootstrap);

int goodix550a_bridge_bootstrap_next_action (Goodix550aBridgeBootstrap       *bootstrap,
                                              Goodix550aBridgeBootstrapAction *action,
                                              uint8_t                          *output,
                                              size_t                            output_length);

int goodix550a_bridge_bootstrap_complete_transfer (Goodix550aBridgeBootstrap *bootstrap,
                                                    const uint8_t                *input,
                                                    size_t                        input_length,
                                                    uint8_t                      *advanced);

int goodix550a_bridge_bootstrap_result (Goodix550aBridgeBootstrap     *bootstrap,
                                         Goodix550aBridgeBootstrapInfo *info);

const char *goodix550a_bridge_bootstrap_last_error (const Goodix550aBridgeBootstrap *bootstrap);

int goodix550a_bridge_recovery_new (Goodix550aBridgeRecovery **recovery);
void goodix550a_bridge_recovery_free (Goodix550aBridgeRecovery *recovery);

int goodix550a_bridge_recovery_next_action (Goodix550aBridgeRecovery       *recovery,
                                             Goodix550aBridgeRecoveryAction *action,
                                             uint8_t                         *output,
                                             size_t                           output_length);

int goodix550a_bridge_recovery_complete_transfer (Goodix550aBridgeRecovery *recovery,
                                                   const uint8_t              *input,
                                                   size_t                      input_length,
                                                   uint8_t                    *advanced);

int goodix550a_bridge_recovery_result (Goodix550aBridgeRecovery     *recovery,
                                        Goodix550aBridgeRecoveryInfo *info);

const char *goodix550a_bridge_recovery_last_error (const Goodix550aBridgeRecovery *recovery);

int goodix550a_bridge_capture_new (Goodix550aBridgeCapture **capture);
void goodix550a_bridge_capture_free (Goodix550aBridgeCapture *capture);

int goodix550a_bridge_capture_next_action (Goodix550aBridgeCapture       *capture,
                                            Goodix550aBridgeCaptureAction *action,
                                            uint8_t                       *output,
                                            size_t                         output_length);

int goodix550a_bridge_capture_complete_transfer (Goodix550aBridgeCapture *capture,
                                                  const uint8_t             *input,
                                                  size_t                     input_length,
                                                  uint8_t                   *advanced);

int goodix550a_bridge_capture_copy_image_u8 (Goodix550aBridgeCapture     *capture,
                                              uint8_t                     *output,
                                              size_t                       output_length,
                                              Goodix550aBridgeCaptureInfo *info);

const char *goodix550a_bridge_capture_last_error (const Goodix550aBridgeCapture *capture);
int goodix550a_bridge_enrollment_new (Goodix550aBridgeEnrollment **enrollment);
void goodix550a_bridge_enrollment_free (Goodix550aBridgeEnrollment *enrollment);

int goodix550a_bridge_enrollment_next_action (Goodix550aBridgeEnrollment       *enrollment,
                                               Goodix550aBridgeEnrollmentAction *action,
                                               uint8_t                          *output,
                                               size_t                            output_length);

int goodix550a_bridge_enrollment_complete_transfer (Goodix550aBridgeEnrollment *enrollment,
                                                     const uint8_t                *input,
                                                     size_t                        input_length,
                                                     uint8_t                      *advanced);

int goodix550a_bridge_enrollment_result (Goodix550aBridgeEnrollment     *enrollment,
                                          Goodix550aBridgeEnrollmentInfo *info);

int goodix550a_bridge_enrollment_start_next_touch (Goodix550aBridgeEnrollment *enrollment);

int goodix550a_bridge_enrollment_copy_tgla (Goodix550aBridgeEnrollment *enrollment,
                                             uint8_t                     *output,
                                             size_t                       output_length,
                                             size_t                      *written);

const char *goodix550a_bridge_enrollment_last_error (const Goodix550aBridgeEnrollment *enrollment);

int goodix550a_bridge_verification_new (const uint8_t                  *tgla,
                                          size_t                          tgla_length,
                                          Goodix550aBridgeVerification **verification);
void goodix550a_bridge_verification_free (Goodix550aBridgeVerification *verification);

int goodix550a_bridge_verification_next_action (Goodix550aBridgeVerification       *verification,
                                                 Goodix550aBridgeVerificationAction *action,
                                                 uint8_t                            *output,
                                                 size_t                              output_length);

int goodix550a_bridge_verification_complete_transfer (Goodix550aBridgeVerification *verification,
                                                       const uint8_t                  *input,
                                                       size_t                          input_length,
                                                       uint8_t                        *advanced);

int goodix550a_bridge_verification_result (Goodix550aBridgeVerification     *verification,
                                             Goodix550aBridgeVerificationInfo *info);

const char *goodix550a_bridge_verification_last_error (const Goodix550aBridgeVerification *verification);

const char *goodix550a_bridge_firmware_name (Goodix550aBridgeFirmware firmware);
const char *goodix550a_bridge_status_message (int status);

#ifdef __cplusplus
}
#endif
