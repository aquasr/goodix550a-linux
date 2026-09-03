// SPDX-License-Identifier: LGPL-2.1-or-later

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fprint.h>

int
main (void)
{
  g_autoptr(FpContext) context = NULL;
  GPtrArray *devices;
  FpDevice *target = NULL;
  FpImage *image = NULL;
  g_autoptr(GError) error = NULL;
  const guchar *pixels;
  gsize pixel_count = 0;
  guchar minimum = 0xff;
  guchar maximum = 0x00;

  if (geteuid () == 0)
    {
      fprintf (stderr,
               "refusing to access the fingerprint reader as root; "
               "install the udev rule and run this probe as the logged-in user\n");
      return EXIT_FAILURE;
    }

  context = fp_context_new ();
  devices = fp_context_get_devices (context);

  for (guint i = 0; i < devices->len; i++)
    {
      FpDevice *device = g_ptr_array_index (devices, i);

      if (g_strcmp0 (fp_device_get_driver (device), "goodix550a") == 0)
        {
          target = device;
          break;
        }
    }

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
  printf ("capture: place finger on sensor\n");
  fflush (stdout);

  image = fp_device_capture_sync (target, TRUE, NULL, &error);
  if (!image)
    {
      fprintf (stderr, "capture=FAIL error=%s\n", error ? error->message : "unknown error");
      g_clear_error (&error);
      if (!fp_device_close_sync (target, NULL, &error))
        fprintf (stderr, "close=FAIL error=%s\n", error ? error->message : "unknown error");
      else
        printf ("close=PASS\n");
      return EXIT_FAILURE;
    }

  pixels = fp_image_get_data (image, &pixel_count);
  if (fp_image_get_width (image) != 80 ||
      fp_image_get_height (image) != 64 ||
      pixel_count != 5120)
    {
      fprintf (stderr,
               "capture=FAIL unexpected image geometry width=%u height=%u bytes=%zu\n",
               fp_image_get_width (image),
               fp_image_get_height (image),
               pixel_count);
      g_object_unref (image);
      g_clear_error (&error);
      if (!fp_device_close_sync (target, NULL, &error))
        fprintf (stderr, "close=FAIL error=%s\n", error ? error->message : "unknown error");
      else
        printf ("close=PASS\n");
      return EXIT_FAILURE;
    }

  for (gsize i = 0; i < pixel_count; i++)
    {
      minimum = MIN (minimum, pixels[i]);
      maximum = MAX (maximum, pixels[i]);
    }

  printf ("capture=PASS width=%u height=%u bytes=%zu min=%u max=%u\n",
          fp_image_get_width (image),
          fp_image_get_height (image),
          pixel_count,
          (guint) minimum,
          (guint) maximum);
  g_object_unref (image);

  g_clear_error (&error);
  if (!fp_device_close_sync (target, NULL, &error))
    {
      fprintf (stderr, "close=FAIL error=%s\n", error ? error->message : "unknown error");
      return EXIT_FAILURE;
    }

  printf ("close=PASS\n");
  return EXIT_SUCCESS;
}
