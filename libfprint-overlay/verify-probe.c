// SPDX-License-Identifier: LGPL-2.1-or-later

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <fprint.h>

#define GOODIX550A_PRINT_VERSION 1u
#define GOODIX550A_FPI_PRINT_RAW 1

typedef struct
{
  gboolean reported;
  gboolean retry;
  gboolean matched;
} VerifyReport;

static void
match_cb (FpDevice *device,
          FpPrint  *match,
          FpPrint  *print,
          gpointer  user_data,
          GError   *error)
{
  VerifyReport *report = user_data;

  (void) device;
  (void) print;

  report->reported = TRUE;
  if (error)
    {
      report->retry = TRUE;
      report->matched = FALSE;
      printf ("verify-report=RETRY code=%d message=%s\n", error->code, error->message);
      return;
    }

  report->retry = FALSE;
  report->matched = match != NULL;
  printf ("verify-report=%s\n", report->matched ? "MATCH" : "NO_MATCH");
}

static FpDevice *
find_target (FpContext *context)
{
  GPtrArray *devices = fp_context_get_devices (context);

  for (guint i = 0; i < devices->len; i++)
    {
      FpDevice *device = g_ptr_array_index (devices, i);

      if (g_strcmp0 (fp_device_get_driver (device), "goodix550a") == 0)
        return device;
    }

  return NULL;
}

static FpPrint *
print_from_tgla_roundtrip (FpDevice      *device,
                           const guint8  *tgla,
                           gsize          tgla_length,
                           gsize         *serialized_length,
                           GError       **error)
{
  g_autoptr(FpPrint) original = NULL;
  g_autoptr(GVariant) bytes = NULL;
  g_autoptr(GVariant) data = NULL;
  g_autofree guchar *serialized = NULL;
  FpPrint *roundtrip;

  original = fp_print_new (device);
  g_object_ref_sink (original);

  bytes = g_variant_ref_sink (g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                                          tgla,
                                                          tgla_length,
                                                          sizeof (guint8)));
  data = g_variant_ref_sink (g_variant_new ("(u@ay)",
                                            GOODIX550A_PRINT_VERSION,
                                            g_variant_ref (bytes)));

  /* Validation adapter only: production enrollment will initialize the same
   * FPI_PRINT_RAW + fpi-data representation from the Rust enrollment result. */
  g_object_set (original,
                "fpi-type", GOODIX550A_FPI_PRINT_RAW,
                "fpi-data", data,
                NULL);

  if (!fp_print_compatible (original, device))
    {
      g_set_error_literal (error,
                           G_IO_ERROR,
                           G_IO_ERROR_INVALID_DATA,
                           "constructed GF3258 print is not compatible with the target device");
      return NULL;
    }

  if (!fp_print_serialize (original, &serialized, serialized_length, error))
    return NULL;

  roundtrip = fp_print_deserialize (serialized, *serialized_length, error);
  if (!roundtrip)
    return NULL;

  if (!fp_print_compatible (roundtrip, device))
    {
      g_object_unref (roundtrip);
      g_set_error_literal (error,
                           G_IO_ERROR,
                           G_IO_ERROR_INVALID_DATA,
                           "deserialized GF3258 print is not compatible with the target device");
      return NULL;
    }

  return roundtrip;
}

int
main (int argc, char **argv)
{
  g_autoptr(FpContext) context = NULL;
  g_autoptr(FpPrint) enrolled_print = NULL;
  g_autoptr(FpPrint) scanned_print = NULL;
  g_autoptr(GError) error = NULL;
  g_autofree gchar *tgla_contents = NULL;
  FpDevice *target;
  VerifyReport report = { 0 };
  gsize tgla_length = 0;
  gsize serialized_length = 0;
  gboolean matched = FALSE;

  if (geteuid () == 0)
    {
      fprintf (stderr,
               "refusing to access the fingerprint reader as root; "
               "install the udev rule and run this probe as the logged-in user\n");
      return EXIT_FAILURE;
    }

  if (argc != 2)
    {
      fprintf (stderr, "usage: %s <template.tgla>\n", argv[0]);
      return EXIT_FAILURE;
    }

  if (!g_file_get_contents (argv[1], &tgla_contents, &tgla_length, &error))
    {
      fprintf (stderr, "template=FAIL error=%s\n", error->message);
      return EXIT_FAILURE;
    }

  if (tgla_length == 0)
    {
      fprintf (stderr, "template=FAIL error=empty TGLA file\n");
      return EXIT_FAILURE;
    }

  context = fp_context_new ();
  target = find_target (context);
  if (!target)
    {
      fprintf (stderr, "goodix550a device was not discovered by this libfprint build\n");
      return EXIT_FAILURE;
    }

  printf ("driver=%s\n", fp_device_get_driver (target));
  printf ("name=%s\n", fp_device_get_name (target));

  if (!fp_device_open_sync (target, NULL, &error))
    {
      fprintf (stderr, "open=FAIL error=%s\n", error ? error->message : "unknown error");
      return EXIT_FAILURE;
    }
  printf ("open=PASS\n");

  enrolled_print = print_from_tgla_roundtrip (target,
                                               (const guint8 *) tgla_contents,
                                               tgla_length,
                                               &serialized_length,
                                               &error);
  if (!enrolled_print)
    {
      fprintf (stderr, "print-roundtrip=FAIL error=%s\n", error ? error->message : "unknown error");
      g_clear_error (&error);
      if (!fp_device_close_sync (target, NULL, &error))
        fprintf (stderr, "close=FAIL error=%s\n", error ? error->message : "unknown error");
      else
        printf ("close=PASS\n");
      return EXIT_FAILURE;
    }

  printf ("print-roundtrip=PASS tgla=%zu serialized=%zu\n",
          tgla_length,
          serialized_length);
  printf ("verify: place finger on sensor\n");
  fflush (stdout);

  if (!fp_device_verify_sync (target,
                              enrolled_print,
                              NULL,
                              match_cb,
                              &report,
                              &matched,
                              &scanned_print,
                              &error))
    {
      fprintf (stderr, "verify=FAIL error=%s\n", error ? error->message : "unknown error");
      g_clear_error (&error);
      if (!fp_device_close_sync (target, NULL, &error))
        fprintf (stderr, "close=FAIL error=%s\n", error ? error->message : "unknown error");
      else
        printf ("close=PASS\n");
      return EXIT_FAILURE;
    }

  if (!report.reported)
    {
      fprintf (stderr, "verify=FAIL error=driver completed without a verify report\n");
      g_clear_error (&error);
      if (!fp_device_close_sync (target, NULL, &error))
        fprintf (stderr, "close=FAIL error=%s\n", error ? error->message : "unknown error");
      else
        printf ("close=PASS\n");
      return EXIT_FAILURE;
    }

  printf ("verify=PASS decision=%s match_bool=%s\n",
          report.retry ? "RETRY" : (report.matched ? "MATCH" : "NO_MATCH"),
          matched ? "true" : "false");

  g_clear_error (&error);
  if (!fp_device_close_sync (target, NULL, &error))
    {
      fprintf (stderr, "close=FAIL error=%s\n", error ? error->message : "unknown error");
      return EXIT_FAILURE;
    }

  printf ("close=PASS\n");
  return EXIT_SUCCESS;
}
