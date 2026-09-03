// SPDX-License-Identifier: LGPL-2.1-or-later

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fprint.h>

#define GOODIX550A_PRINT_VERSION 1u
#define GOODIX550A_PRINT_TYPE "(uay)"

typedef struct
{
  guint retries;
  gint last_completed;
} EnrollProgress;

typedef struct
{
  gboolean reported;
  gboolean retry;
  gboolean matched;
} VerifyReport;

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

static void
enroll_progress_cb (FpDevice *device,
                    gint      completed_stages,
                    FpPrint  *print,
                    gpointer  user_data,
                    GError   *error)
{
  EnrollProgress *progress = user_data;
  gint total = fp_device_get_nr_enroll_stages (device);

  (void) print;
  progress->last_completed = completed_stages;

  if (error)
    {
      progress->retries++;
      printf ("enroll-progress=RETRY completed=%d/%d code=%d message=%s\n",
              completed_stages,
              total,
              error->code,
              error->message);
      printf ("enroll: retry the touch\n");
      fflush (stdout);
      return;
    }

  printf ("enroll-progress=PASS completed=%d/%d\n", completed_stages, total);
  if (completed_stages < total)
    printf ("enroll: place finger for the next sample\n");
  fflush (stdout);
}

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

static gboolean
extract_tgla (FpPrint        *print,
              const guint8  **tgla,
              gsize          *tgla_length,
              GVariant      **print_data_out,
              GVariant      **tgla_variant_out,
              GError        **error)
{
  g_autoptr(GVariant) print_data = NULL;
  g_autoptr(GVariant) tgla_variant = NULL;
  guint32 version = 0;

  g_object_get (print, "fpi-data", &print_data, NULL);
  if (!print_data || !g_variant_is_of_type (print_data, G_VARIANT_TYPE (GOODIX550A_PRINT_TYPE)))
    {
      g_set_error_literal (error,
                           G_IO_ERROR,
                           G_IO_ERROR_INVALID_DATA,
                           "enrolled print is not a versioned TGLA payload");
      return FALSE;
    }

  g_variant_get (print_data, "(u@ay)", &version, &tgla_variant);
  if (version != GOODIX550A_PRINT_VERSION)
    {
      g_set_error (error,
                   G_IO_ERROR,
                   G_IO_ERROR_INVALID_DATA,
                   "unexpected GF3258 print-data version %u",
                   version);
      return FALSE;
    }

  *tgla = g_variant_get_fixed_array (tgla_variant, tgla_length, sizeof (guint8));
  if (!*tgla || *tgla_length == 0)
    {
      g_set_error_literal (error,
                           G_IO_ERROR,
                           G_IO_ERROR_INVALID_DATA,
                           "enrolled print contains an empty TGLA payload");
      return FALSE;
    }

  *print_data_out = g_steal_pointer (&print_data);
  *tgla_variant_out = g_steal_pointer (&tgla_variant);
  return TRUE;
}

int
main (int argc, char **argv)
{
  g_autoptr(FpContext) context = NULL;
  g_autoptr(FpPrint) template_print = NULL;
  g_autoptr(FpPrint) enrolled_print = NULL;
  g_autoptr(FpPrint) roundtrip_print = NULL;
  g_autoptr(FpPrint) scanned_print = NULL;
  g_autoptr(GVariant) print_data = NULL;
  g_autoptr(GVariant) tgla_variant = NULL;
  g_autoptr(GError) error = NULL;
  g_autofree guchar *serialized = NULL;
  FpDevice *target;
  EnrollProgress progress = { 0 };
  VerifyReport report = { 0 };
  const guint8 *tgla = NULL;
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
      fprintf (stderr, "usage: %s <output.tgla>\n", argv[0]);
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
  printf ("enroll-stages=%d\n", fp_device_get_nr_enroll_stages (target));

  if (fp_device_get_nr_enroll_stages (target) != 12)
    {
      fprintf (stderr, "enroll=FAIL error=driver did not advertise 12 enrollment stages\n");
      return EXIT_FAILURE;
    }

  if (!fp_device_open_sync (target, NULL, &error))
    {
      fprintf (stderr, "open=FAIL error=%s\n", error ? error->message : "unknown error");
      return EXIT_FAILURE;
    }
  printf ("open=PASS\n");

  template_print = fp_print_new (target);
  g_object_ref_sink (template_print);
  fp_print_set_finger (template_print, FP_FINGER_RIGHT_INDEX);

  printf ("enroll: place the same finger for each sample; lift/reposition after each accepted touch\n");
  fflush (stdout);

  enrolled_print = fp_device_enroll_sync (target,
                                           template_print,
                                           NULL,
                                           enroll_progress_cb,
                                           &progress,
                                           &error);
  if (!enrolled_print)
    {
      fprintf (stderr, "enroll=FAIL error=%s\n", error ? error->message : "unknown error");
      g_clear_error (&error);
      goto close_fail;
    }

  printf ("enroll=PASS completed=%d retries=%u\n",
          progress.last_completed,
          progress.retries);

  if (!fp_print_compatible (enrolled_print, target))
    {
      fprintf (stderr, "enroll-print=FAIL error=returned print is not compatible\n");
      goto close_fail;
    }

  if (!fp_print_serialize (enrolled_print, &serialized, &serialized_length, &error))
    {
      fprintf (stderr, "serialize=FAIL error=%s\n", error ? error->message : "unknown error");
      g_clear_error (&error);
      goto close_fail;
    }

  roundtrip_print = fp_print_deserialize (serialized, serialized_length, &error);
  if (!roundtrip_print)
    {
      fprintf (stderr, "deserialize=FAIL error=%s\n", error ? error->message : "unknown error");
      g_clear_error (&error);
      goto close_fail;
    }

  if (!fp_print_compatible (roundtrip_print, target))
    {
      fprintf (stderr, "enroll-roundtrip=FAIL error=deserialized print is not compatible\n");
      goto close_fail;
    }

  if (!extract_tgla (roundtrip_print,
                     &tgla,
                     &tgla_length,
                     &print_data,
                     &tgla_variant,
                     &error))
    {
      fprintf (stderr, "enroll-roundtrip=FAIL error=%s\n", error ? error->message : "unknown error");
      g_clear_error (&error);
      goto close_fail;
    }

  if (!g_file_set_contents (argv[1], (const gchar *) tgla, (gssize) tgla_length, &error))
    {
      fprintf (stderr, "tgla-write=FAIL error=%s\n", error ? error->message : "unknown error");
      g_clear_error (&error);
      goto close_fail;
    }

  printf ("enroll-roundtrip=PASS serialized=%zu tgla=%zu output=%s\n",
          serialized_length,
          tgla_length,
          argv[1]);
  printf ("verify-new-print: place the newly enrolled finger on sensor\n");
  fflush (stdout);

  if (!fp_device_verify_sync (target,
                              roundtrip_print,
                              NULL,
                              match_cb,
                              &report,
                              &matched,
                              &scanned_print,
                              &error))
    {
      fprintf (stderr, "verify=FAIL error=%s\n", error ? error->message : "unknown error");
      g_clear_error (&error);
      goto close_fail;
    }

  if (!report.reported)
    {
      fprintf (stderr, "verify=FAIL error=driver completed without a verify report\n");
      goto close_fail;
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

  return (report.retry || !report.matched || !matched) ? EXIT_FAILURE : EXIT_SUCCESS;

close_fail:
  g_clear_error (&error);
  if (!fp_device_close_sync (target, NULL, &error))
    fprintf (stderr, "close=FAIL error=%s\n", error ? error->message : "unknown error");
  else
    printf ("close=PASS\n");
  return EXIT_FAILURE;
}
