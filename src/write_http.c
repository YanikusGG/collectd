/**
 * collectd - src/write_http.c
 * Copyright (C) 2009       Paul Sadauskas
 * Copyright (C) 2009       Doug MacEachern
 * Copyright (C) 2007-2020  Florian octo Forster
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Florian octo Forster <octo at collectd.org>
 *   Doug MacEachern <dougm@hyperic.com>
 *   Paul Sadauskas <psadauskas@gmail.com>
 **/

#include "collectd.h"

#include "plugin.h"
#include "utils/avltree/avltree.h"
#include "utils/cmds/putmetric.h"
#include "utils/common/common.h"
#include "utils/curl_stats/curl_stats.h"
#include "utils/format_influxdb/format_influxdb.h"
#include "utils/format_json/format_json.h"
#include "utils/format_kairosdb/format_kairosdb.h"

#include <curl/curl.h>

#ifndef WRITE_HTTP_DEFAULT_PREFIX
#define WRITE_HTTP_DEFAULT_PREFIX "collectd"
#endif

#ifndef WRITE_HTTP_RESPONSE_BUFFER_SIZE
#define WRITE_HTTP_RESPONSE_BUFFER_SIZE 1024
#endif

/*
 * Private variables
 */
struct wh_callback_s {
  char *name;

  char *location;
  char *user;
  char *pass;
  char *credentials;
  bool verify_peer;
  bool verify_host;
  char *cacert;
  char *capath;
  char *clientkey;
  char *clientcert;
  char *clientkeypass;
  long sslversion;
  bool store_rates;
  bool log_http_error;
  int low_speed_limit;
  time_t low_speed_time;
  int timeout;

#define WH_FORMAT_COMMAND 0
#define WH_FORMAT_JSON 1
#define WH_FORMAT_KAIROSDB 2
#define WH_FORMAT_INFLUXDB 3
#define WH_FORMAT_OTLP_JSON 5
  int format;
  bool send_metrics;
  bool send_notifications;

  pthread_mutex_t curl_lock;
  CURL *curl;
  curl_stats_t *curl_stats;
  struct curl_slist *headers;
  char curl_errbuf[CURL_ERROR_SIZE];

  pthread_mutex_t send_buffer_lock;
  strbuf_t send_buffer;
  cdtime_t send_buffer_init_time;
  resource_metrics_set_t resource_metrics;

  c_avl_tree_t *staged_metrics;         // char* metric_identity() -> NULL
  c_avl_tree_t *staged_metric_families; // char* fam->name -> metric_family_t*

  char response_buffer[WRITE_HTTP_RESPONSE_BUFFER_SIZE];
  unsigned int response_buffer_pos;

  int data_ttl;
  char *metrics_prefix;

  char *unix_socket_path;

  int reference_count;
};
typedef struct wh_callback_s wh_callback_t;

/* libcurl may call this multiple times depending on how big the server's
 * http response is
 */
static size_t wh_curl_write_callback(char *ptr, size_t size, size_t nmemb,
                                     void *userdata) {

  wh_callback_t *cb = (wh_callback_t *)userdata;
  unsigned int len = 0;

  if ((cb->response_buffer_pos + nmemb) > sizeof(cb->response_buffer))
    len = sizeof(cb->response_buffer) - cb->response_buffer_pos;
  else
    len = nmemb;

  DEBUG(
      "write_http plugin: curl callback nmemb=%zu buffer_pos=%u write_len=%u ",
      nmemb, cb->response_buffer_pos, len);

  memcpy(cb->response_buffer + cb->response_buffer_pos, ptr, len);
  cb->response_buffer_pos += len;
  cb->response_buffer[sizeof(cb->response_buffer) - 1] = '\0';

  /* Always return nmemb even if we write less so libcurl won't throw an error
   */
  return nmemb;

} /* wh_curl_write_callback */

static void wh_log_http_error(wh_callback_t *cb) {
  if (!cb->log_http_error) {
    return;
  }

  long http_code = 0;
  curl_easy_getinfo(cb->curl, CURLINFO_RESPONSE_CODE, &http_code);

  if (http_code != 200) {
    INFO("write_http plugin: HTTP Error code: %lu", http_code);
  }
}

/* must hold cb->curl_lock when calling */
static int wh_post(wh_callback_t *cb, char const *data, long size) {
  pthread_mutex_lock(&cb->curl_lock);

  cb->response_buffer_pos = 0;
  curl_easy_setopt(cb->curl, CURLOPT_URL, cb->location);
  curl_easy_setopt(cb->curl, CURLOPT_POSTFIELDSIZE, size);
  curl_easy_setopt(cb->curl, CURLOPT_POSTFIELDS, data);
  curl_easy_setopt(cb->curl, CURLOPT_WRITEFUNCTION, &wh_curl_write_callback);
  curl_easy_setopt(cb->curl, CURLOPT_WRITEDATA, (void *)cb);
  int status = curl_easy_perform(cb->curl);

  wh_log_http_error(cb);

  if (cb->curl_stats != NULL) {
    int rc = curl_stats_dispatch(cb->curl_stats, cb->curl, NULL, "write_http",
                                 cb->name);
    if (rc != 0) {
      ERROR("write_http plugin: curl_stats_dispatch failed with status %d", rc);
    }
  }

  if (status != CURLE_OK) {
    ERROR("write_http plugin: curl_easy_perform failed with status %d: %s",
          status, cb->curl_errbuf);
    if (strlen(cb->response_buffer) > 0) {
      ERROR("write_http plugin: curl_response=%s", cb->response_buffer);
    }
  } else {
    DEBUG("write_http plugin: curl_response=%s", cb->response_buffer);
  }

  pthread_mutex_unlock(&cb->curl_lock);
  return status;
} /* wh_post */

static int wh_callback_init(wh_callback_t *cb) {
  if (cb->curl != NULL) {
    return 0;
  }

  cb->curl = curl_easy_init();
  if (cb->curl == NULL) {
    ERROR("curl plugin: curl_easy_init failed.");
    return -1;
  }

  if (cb->low_speed_limit > 0 && cb->low_speed_time > 0) {
    curl_easy_setopt(cb->curl, CURLOPT_LOW_SPEED_LIMIT,
                     (long)(cb->low_speed_limit * cb->low_speed_time));
    curl_easy_setopt(cb->curl, CURLOPT_LOW_SPEED_TIME,
                     (long)cb->low_speed_time);
  }

#ifdef HAVE_CURLOPT_TIMEOUT_MS
  if (cb->timeout > 0)
    curl_easy_setopt(cb->curl, CURLOPT_TIMEOUT_MS, (long)cb->timeout);
#endif

  curl_easy_setopt(cb->curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(cb->curl, CURLOPT_USERAGENT, COLLECTD_USERAGENT);

  cb->headers = curl_slist_append(cb->headers, "Accept:  */*");
  switch (cb->format) {
  case WH_FORMAT_JSON:
  case WH_FORMAT_KAIROSDB:
  case WH_FORMAT_OTLP_JSON:
    cb->headers =
        curl_slist_append(cb->headers, "Content-Type: application/json");

  default:
    cb->headers = curl_slist_append(cb->headers, "Content-Type: text/plain");
  }
  cb->headers = curl_slist_append(cb->headers, "Expect:");
  curl_easy_setopt(cb->curl, CURLOPT_HTTPHEADER, cb->headers);

  curl_easy_setopt(cb->curl, CURLOPT_ERRORBUFFER, cb->curl_errbuf);
  curl_easy_setopt(cb->curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(cb->curl, CURLOPT_MAXREDIRS, 50L);

  if (cb->user != NULL) {
#ifdef HAVE_CURLOPT_USERNAME
    curl_easy_setopt(cb->curl, CURLOPT_USERNAME, cb->user);
    curl_easy_setopt(cb->curl, CURLOPT_PASSWORD,
                     (cb->pass == NULL) ? "" : cb->pass);
#else
    size_t credentials_size;

    credentials_size = strlen(cb->user) + 2;
    if (cb->pass != NULL)
      credentials_size += strlen(cb->pass);

    cb->credentials = malloc(credentials_size);
    if (cb->credentials == NULL) {
      ERROR("curl plugin: malloc failed.");
      return -1;
    }

    snprintf(cb->credentials, credentials_size, "%s:%s", cb->user,
             (cb->pass == NULL) ? "" : cb->pass);
    curl_easy_setopt(cb->curl, CURLOPT_USERPWD, cb->credentials);
#endif
    curl_easy_setopt(cb->curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
  }

  curl_easy_setopt(cb->curl, CURLOPT_SSL_VERIFYPEER, (long)cb->verify_peer);
  curl_easy_setopt(cb->curl, CURLOPT_SSL_VERIFYHOST, cb->verify_host ? 2L : 0L);
  curl_easy_setopt(cb->curl, CURLOPT_SSLVERSION, cb->sslversion);
  if (cb->cacert != NULL)
    curl_easy_setopt(cb->curl, CURLOPT_CAINFO, cb->cacert);
  if (cb->capath != NULL)
    curl_easy_setopt(cb->curl, CURLOPT_CAPATH, cb->capath);

  if (cb->clientkey != NULL && cb->clientcert != NULL) {
    curl_easy_setopt(cb->curl, CURLOPT_SSLKEY, cb->clientkey);
    curl_easy_setopt(cb->curl, CURLOPT_SSLCERT, cb->clientcert);

    if (cb->clientkeypass != NULL)
      curl_easy_setopt(cb->curl, CURLOPT_SSLKEYPASSWD, cb->clientkeypass);
  }
#ifdef CURL_VERSION_UNIX_SOCKETS
  if (cb->unix_socket_path) {
    curl_easy_setopt(cb->curl, CURLOPT_UNIX_SOCKET_PATH, cb->unix_socket_path);
  }
#endif // CURL_VERSION_UNIX_SOCKETS

  strbuf_reset(&cb->send_buffer);

  return 0;
} /* int wh_callback_init */

static int flush_resource_metrics(wh_callback_t *cb) {
  /* You must hold cb->send_buffer_lock when calling. */
  strbuf_t buf = STRBUF_CREATE;
  int status = 0;
  switch (cb->format) {
  case WH_FORMAT_OTLP_JSON:
    status = format_json_open_telemetry(&buf, &cb->resource_metrics);
    if (status != 0) {
      ERROR("write_http plugin: format_json_open_telemetry failed: %s",
            STRERROR(status));
    }
    break;

  default:
    ERROR("write_http plugin: Unexpected format: %d", cb->format);
    status = EINVAL;
  }

  if (status != 0) {
    pthread_mutex_unlock(&cb->send_buffer_lock);
    STRBUF_DESTROY(buf);
    return status;
  }

  resource_metrics_reset(&cb->resource_metrics);
  cb->send_buffer_init_time = cdtime();

  pthread_mutex_unlock(&cb->send_buffer_lock);

  status = wh_post(cb, buf.ptr, buf.pos);
  STRBUF_DESTROY(buf);
  return status;
}

static int wh_flush(cdtime_t timeout,
                    const char *identifier __attribute__((unused)),
                    user_data_t *user_data) {
  if (user_data == NULL)
    return -EINVAL;

  wh_callback_t *cb = user_data->data;

  pthread_mutex_lock(&cb->send_buffer_lock);

  if (wh_callback_init(cb) != 0) {
    ERROR("write_http plugin: wh_callback_init failed.");
    pthread_mutex_unlock(&cb->send_buffer_lock);
    return -1;
  }

  /* timeout == 0  => flush unconditionally */
  if (timeout > 0) {
    if ((cb->send_buffer_init_time + timeout) > cdtime()) {
      pthread_mutex_unlock(&cb->send_buffer_lock);
      return 0;
    }
  }

  if (cb->format == WH_FORMAT_OTLP_JSON) {
    /* cb->send_buffer_lock is unlocked in flush_resource_metrics. */
    return flush_resource_metrics(cb);
  }

  if (cb->send_buffer.pos == 0) {
    cb->send_buffer_init_time = cdtime();
    pthread_mutex_unlock(&cb->send_buffer_lock);
    return 0;
  }

  char const *json = strdup(cb->send_buffer.ptr);
  const size_t size = cb->send_buffer.pos;
  strbuf_reset(&cb->send_buffer);
  cb->send_buffer_init_time = cdtime();
  pthread_mutex_unlock(&cb->send_buffer_lock);

  if (json == NULL) {
    return ENOMEM;
  }

  return wh_post(cb, json, size);
} /* int wh_flush */

static void wh_callback_free(void *data) {
  if (data == NULL)
    return;

  wh_callback_t *cb = data;

  /* cb is used as user_data in:
   * - plugin_register_write
   * - plugin_register_flush
   * - plugin_register_notification
   * We can not rely on them being torn down in a known order.
   * Only actually free the structure when all references are dropped. */
  pthread_mutex_lock(&cb->curl_lock);
  cb->reference_count--;
  if (cb->reference_count > 0) {
    pthread_mutex_unlock(&cb->curl_lock);
    return;
  }

  wh_flush(/* timeout = */ 0, NULL, &(user_data_t){.data = cb});

  if (cb->curl != NULL) {
    curl_easy_cleanup(cb->curl);
    cb->curl = NULL;
  }

  curl_stats_destroy(cb->curl_stats);
  cb->curl_stats = NULL;

  if (cb->headers != NULL) {
    curl_slist_free_all(cb->headers);
    cb->headers = NULL;
  }

  sfree(cb->name);
  sfree(cb->location);
  sfree(cb->user);
  sfree(cb->pass);
  sfree(cb->credentials);
  sfree(cb->cacert);
  sfree(cb->capath);
  sfree(cb->clientkey);
  sfree(cb->clientcert);
  sfree(cb->clientkeypass);
  sfree(cb->metrics_prefix);

  pthread_mutex_unlock(&cb->curl_lock);
  pthread_mutex_destroy(&cb->curl_lock);
  pthread_mutex_destroy(&cb->send_buffer_lock);

  sfree(cb);
} /* void wh_callback_free */

static int wh_write_command(metric_family_t const *fam, wh_callback_t *cb) {
  pthread_mutex_lock(&cb->send_buffer_lock);

  int ret = 0;
  for (size_t i = 0; i < fam->metric.num; i++) {
    metric_t const *m = fam->metric.ptr;

    int status = cmd_format_putmetric(&cb->send_buffer, m);
    if (status != 0) {
      ERROR("write_http plugin: cmd_format_putmetric failed: %s",
            STRERROR(status));
      ret = ret ? ret : status;
      continue;
    }

    strbuf_print(&cb->send_buffer, "\n");
  }

  pthread_mutex_unlock(&cb->send_buffer_lock);
  return ret;
} /* int wh_write_command */

static int wh_write_json(metric_family_t const *fam, wh_callback_t *cb) {
  pthread_mutex_lock(&cb->send_buffer_lock);

  int status =
      format_json_metric_family(&cb->send_buffer, fam, cb->store_rates);
  if (status != 0) {
    pthread_mutex_unlock(&cb->send_buffer_lock);
    ERROR("write_http plugin: format_json_metric_family failed: %s",
          STRERROR(status));
    return status;
  }

  pthread_mutex_unlock(&cb->send_buffer_lock);
  return 0;
} /* int wh_write_json */

static int wh_write_kairosdb(metric_family_t const *fam, wh_callback_t *cb) {
  format_kairosdb_opts_t opts = {
      .store_rates = cb->store_rates,
      .ttl_secs = cb->data_ttl,
      .metrics_prefix = cb->metrics_prefix,
  };

  pthread_mutex_lock(&cb->send_buffer_lock);

  int status = format_kairosdb_metric_family(&cb->send_buffer, fam, &opts);
  if (status != 0) {
    pthread_mutex_unlock(&cb->send_buffer_lock);
    ERROR("write_http plugin: format_kairosdb_metric_family failed: %s",
          STRERROR(status));
    return status;
  }

  pthread_mutex_unlock(&cb->send_buffer_lock);
  return 0;
} /* int wh_write_kairosdb */

static int wh_write_influxdb(metric_family_t const *fam, wh_callback_t *cb) {
  pthread_mutex_lock(&cb->send_buffer_lock);

  for (size_t i = 0; i < fam->metric.num; i++) {
    metric_t const *m = fam->metric.ptr + i;
    int status = format_influxdb_point(&cb->send_buffer, m, cb->store_rates);
    if (status != 0) {
      pthread_mutex_unlock(&cb->send_buffer_lock);
      ERROR("write_http plugin: format_influxdb_point failed: %s",
            STRERROR(status));
      return status;
    }
  }

  pthread_mutex_unlock(&cb->send_buffer_lock);
  return 0;
} /* wh_write_influxdb */

static int wh_write_resource_metrics(metric_family_t const *fam,
                                     wh_callback_t *cb) {
  pthread_mutex_lock(&cb->send_buffer_lock);
  int status = resource_metrics_add(&cb->resource_metrics, fam);
  pthread_mutex_unlock(&cb->send_buffer_lock);

  if (status < 0) {
    ERROR("write_http plugin: resource_metrics_add failed: %s",
          STRERROR(status));
    return status;
  }
  return 0;
}

static int wh_write(metric_family_t const *fam, user_data_t *user_data) {
  if ((fam == NULL) || (user_data == NULL)) {
    return EINVAL;
  }

  wh_callback_t *cb = user_data->data;

  assert(cb->send_metrics);

  int status = EINVAL;
  switch (cb->format) {
  case WH_FORMAT_JSON:
    status = wh_write_json(fam, cb);
    break;
  case WH_FORMAT_KAIROSDB:
    status = wh_write_kairosdb(fam, cb);
    break;
  case WH_FORMAT_INFLUXDB:
    status = wh_write_influxdb(fam, cb);
    break;
  case WH_FORMAT_OTLP_JSON:
    status = wh_write_resource_metrics(fam, cb);
    break;
  default:
    status = wh_write_command(fam, cb);
    break;
  }
  return status;
} /* int wh_write */

static int wh_notify(notification_t const *n, user_data_t *ud) {
  wh_callback_t *cb;
  char alert[4096];
  int status;

  if ((ud == NULL) || (ud->data == NULL))
    return EINVAL;

  cb = ud->data;
  assert(cb->send_notifications);

  status = format_json_notification(alert, sizeof(alert), n);
  if (status != 0) {
    ERROR("write_http plugin: formatting notification failed");
    return status;
  }

  pthread_mutex_lock(&cb->send_buffer_lock);
  if (wh_callback_init(cb) != 0) {
    ERROR("write_http plugin: wh_callback_init failed.");
    pthread_mutex_unlock(&cb->send_buffer_lock);
    return -1;
  }

  status = wh_post(cb, alert, -1);
  pthread_mutex_unlock(&cb->send_buffer_lock);

  return status;
} /* int wh_notify */

static int config_set_format(wh_callback_t *cb, oconfig_item_t *ci) {
  char *string;

  if ((ci->values_num != 1) || (ci->values[0].type != OCONFIG_TYPE_STRING)) {
    WARNING("write_http plugin: The `%s' config option "
            "needs exactly one string argument.",
            ci->key);
    return -1;
  }

  string = ci->values[0].value.string;
  if (strcasecmp("Command", string) == 0)
    cb->format = WH_FORMAT_COMMAND;
  else if (strcasecmp("JSON", string) == 0)
    cb->format = WH_FORMAT_JSON;
  else if (strcasecmp("KAIROSDB", string) == 0)
    cb->format = WH_FORMAT_KAIROSDB;
  else if (strcasecmp("INFLUXDB", string) == 0)
    cb->format = WH_FORMAT_INFLUXDB;
  else if (strcasecmp("OTLP_JSON", string) == 0)
    cb->format = WH_FORMAT_OTLP_JSON;
  else {
    ERROR("write_http plugin: Invalid format string: %s", string);
    return -1;
  }

  return 0;
} /* int config_set_format */

static int wh_config_append_string(const char *name, struct curl_slist **dest,
                                   oconfig_item_t *ci) {
  struct curl_slist *temp = NULL;
  if ((ci->values_num != 1) || (ci->values[0].type != OCONFIG_TYPE_STRING)) {
    WARNING("write_http plugin: `%s' needs exactly one string argument.", name);
    return -1;
  }

  temp = curl_slist_append(*dest, ci->values[0].value.string);
  if (temp == NULL)
    return -1;

  *dest = temp;

  return 0;
} /* int wh_config_append_string */

static int wh_config_node(oconfig_item_t *ci) {
  wh_callback_t *cb;
  int buffer_size = 0;
  char callback_name[DATA_MAX_NAME_LEN];
  int status = 0;

  cb = calloc(1, sizeof(*cb));
  if (cb == NULL) {
    ERROR("write_http plugin: calloc failed.");
    return -1;
  }
  cb->verify_peer = true;
  cb->verify_host = true;
  cb->format = WH_FORMAT_COMMAND;
  cb->sslversion = CURL_SSLVERSION_DEFAULT;
  cb->low_speed_limit = 0;
  cb->timeout = 0;
  cb->log_http_error = false;
  cb->headers = NULL;
  cb->send_metrics = true;
  cb->send_notifications = false;
  cb->data_ttl = 0;
  cb->metrics_prefix = strdup(WRITE_HTTP_DEFAULT_PREFIX);
  cb->curl_stats = NULL;
  cb->unix_socket_path = NULL;

  if (cb->metrics_prefix == NULL) {
    ERROR("write_http plugin: strdup failed.");
    sfree(cb);
    return -1;
  }

  pthread_mutex_init(&cb->curl_lock, /* attr = */ NULL);
  pthread_mutex_init(&cb->send_buffer_lock, /* attr = */ NULL);

  cf_util_get_string(ci, &cb->name);

  /* FIXME: Remove this legacy mode in version 6. */
  if (strcasecmp("URL", ci->key) == 0)
    cf_util_get_string(ci, &cb->location);

  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;

    if (strcasecmp("URL", child->key) == 0)
      status = cf_util_get_string(child, &cb->location);
    else if (strcasecmp("User", child->key) == 0)
      status = cf_util_get_string(child, &cb->user);
    else if (strcasecmp("Password", child->key) == 0)
      status = cf_util_get_string(child, &cb->pass);
    else if (strcasecmp("VerifyPeer", child->key) == 0)
      status = cf_util_get_boolean(child, &cb->verify_peer);
    else if (strcasecmp("VerifyHost", child->key) == 0)
      status = cf_util_get_boolean(child, &cb->verify_host);
    else if (strcasecmp("CACert", child->key) == 0)
      status = cf_util_get_string(child, &cb->cacert);
    else if (strcasecmp("CAPath", child->key) == 0)
      status = cf_util_get_string(child, &cb->capath);
    else if (strcasecmp("ClientKey", child->key) == 0)
      status = cf_util_get_string(child, &cb->clientkey);
    else if (strcasecmp("ClientCert", child->key) == 0)
      status = cf_util_get_string(child, &cb->clientcert);
    else if (strcasecmp("ClientKeyPass", child->key) == 0)
      status = cf_util_get_string(child, &cb->clientkeypass);
    else if (strcasecmp("SSLVersion", child->key) == 0) {
      char *value = NULL;

      status = cf_util_get_string(child, &value);
      if (status != 0)
        break;

      if (value == NULL || strcasecmp("default", value) == 0)
        cb->sslversion = CURL_SSLVERSION_DEFAULT;
      else if (strcasecmp("SSLv2", value) == 0)
        cb->sslversion = CURL_SSLVERSION_SSLv2;
      else if (strcasecmp("SSLv3", value) == 0)
        cb->sslversion = CURL_SSLVERSION_SSLv3;
      else if (strcasecmp("TLSv1", value) == 0)
        cb->sslversion = CURL_SSLVERSION_TLSv1;
#if (LIBCURL_VERSION_MAJOR > 7) ||                                             \
    (LIBCURL_VERSION_MAJOR == 7 && LIBCURL_VERSION_MINOR >= 34)
      else if (strcasecmp("TLSv1_0", value) == 0)
        cb->sslversion = CURL_SSLVERSION_TLSv1_0;
      else if (strcasecmp("TLSv1_1", value) == 0)
        cb->sslversion = CURL_SSLVERSION_TLSv1_1;
      else if (strcasecmp("TLSv1_2", value) == 0)
        cb->sslversion = CURL_SSLVERSION_TLSv1_2;
#endif
      else {
        ERROR("write_http plugin: Invalid SSLVersion "
              "option: %s.",
              value);
        status = EINVAL;
      }

      sfree(value);
    } else if (strcasecmp("Format", child->key) == 0)
      status = config_set_format(cb, child);
    else if (strcasecmp("Metrics", child->key) == 0)
      cf_util_get_boolean(child, &cb->send_metrics);
    else if (strcasecmp("Statistics", child->key) == 0) {
      cb->curl_stats = curl_stats_from_config(child);
      if (cb->curl_stats == NULL)
        status = -1;
    } else if (strcasecmp("Notifications", child->key) == 0)
      status = cf_util_get_boolean(child, &cb->send_notifications);
    else if (strcasecmp("StoreRates", child->key) == 0)
      status = cf_util_get_boolean(child, &cb->store_rates);
    else if (strcasecmp("BufferSize", child->key) == 0)
      status = cf_util_get_int(child, &buffer_size);
    else if (strcasecmp("LowSpeedLimit", child->key) == 0)
      status = cf_util_get_int(child, &cb->low_speed_limit);
    else if (strcasecmp("Timeout", child->key) == 0)
      status = cf_util_get_int(child, &cb->timeout);
    else if (strcasecmp("LogHttpError", child->key) == 0)
      status = cf_util_get_boolean(child, &cb->log_http_error);
    else if (strcasecmp("Header", child->key) == 0)
      status = wh_config_append_string("Header", &cb->headers, child);
    else if (strcasecmp("TTL", child->key) == 0)
      status = cf_util_get_int(child, &cb->data_ttl);
    else if (strcasecmp("Prefix", child->key) == 0)
      status = cf_util_get_string(child, &cb->metrics_prefix);
    else if (strcasecmp("UnixSocket", child->key) == 0) {
#ifdef CURL_VERSION_UNIX_SOCKETS
      status = cf_util_get_string(child, &cb->unix_socket_path);
#else
      WARNING("libcurl < 7.40.0, UnixSocket config is ignored");
#endif // CURL_VERSION_UNIX_SOCKETS
    } else {
      ERROR("write_http plugin: Invalid configuration "
            "option: %s.",
            child->key);
      status = EINVAL;
    }

    if (status != 0)
      break;
  }

  if (status != 0) {
    wh_callback_free(cb);
    return status;
  }

  if (cb->location == NULL) {
    ERROR("write_http plugin: no URL defined for instance '%s'", cb->name);
    wh_callback_free(cb);
    return -1;
  }

  if (!cb->send_metrics && !cb->send_notifications) {
    ERROR("write_http plugin: Neither metrics nor notifications "
          "are enabled for \"%s\".",
          cb->name);
    wh_callback_free(cb);
    return -1;
  }

  if (strlen(cb->metrics_prefix) == 0)
    sfree(cb->metrics_prefix);

  if (cb->low_speed_limit > 0)
    cb->low_speed_time = CDTIME_T_TO_TIME_T(plugin_get_interval());

  cb->send_buffer = STRBUF_CREATE;

  snprintf(callback_name, sizeof(callback_name), "write_http/%s", cb->name);
  DEBUG("write_http: Registering write callback '%s' with URL '%s'",
        callback_name, cb->location);

  user_data_t user_data = {
      .data = cb,
      .free_func = wh_callback_free,
  };

  if (cb->send_metrics) {
    /* This causes wh_flush to be called periodically. */
    plugin_ctx_t ctx = plugin_get_ctx();
    ctx.flush_interval = plugin_get_interval();
    plugin_set_ctx(ctx);

    cb->reference_count++;
    plugin_register_write(callback_name, wh_write, &user_data);

    cb->reference_count++;
    plugin_register_flush(callback_name, wh_flush, &user_data);
  }

  if (cb->send_notifications) {
    cb->reference_count++;
    plugin_register_notification(callback_name, wh_notify, &user_data);
  }

  return 0;
} /* int wh_config_node */

static int wh_config(oconfig_item_t *ci) {
  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;

    if (strcasecmp("Node", child->key) == 0) {
      wh_config_node(child);
    } else {
      ERROR("write_http plugin: Invalid configuration option: %s.", child->key);
    }
  }

  return 0;
} /* int wh_config */

static int wh_init(void) {
  /* Call this while collectd is still single-threaded to avoid
   * initialization issues in libgcrypt. */
  curl_global_init(CURL_GLOBAL_SSL);
  return 0;
} /* int wh_init */

void module_register(void) {
  plugin_register_complex_config("write_http", wh_config);
  plugin_register_init("write_http", wh_init);
} /* void module_register */
