/**
 * collectd - src/notify_telegram.c
 * Copyright (C) 2023  Yan Anikiev
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *   Yan Anikiev <anikievyan@gmail.com>
 **/

#include "collectd.h"

#include "plugin.h"
#include "utils/common/common.h"

#define MAXSTRING 1024

static const char *config_keys[] = {"Greeting"};
static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);

static char *greeting;

static pthread_mutex_t greeting_lock = PTHREAD_MUTEX_INITIALIZER;

#define DEFAULT_GREETING "This is telegram plugin!"

static int notify_telegram_init(void) {
    return 0;
}

static int notify_telegram_shutdown(void) {
    return 0;
}

static int notify_telegram_config(const char *key, const char *value) {
    if (0 == strcasecmp(key, "Greeting")) {
        sfree(greeting);
        greeting = strdup(value);
    } else {
        return -1;
    }
    return 0;
}

static int notify_telegram_notification(const notification_t *n, user_data_t __attribute__((unused)) * user_data) {
    char buf[MAXSTRING] = "";
    char *buf_ptr = buf;
    int buf_len = sizeof(buf);
    int status;

    status = snprintf(
        buf_ptr, buf_len, "Notification: severity = %s",
        (n->severity == NOTIF_FAILURE)
            ? "FAILURE"
            : ((n->severity == NOTIF_WARNING)
                ? "WARNING"
                : ((n->severity == NOTIF_OKAY)
                    ? "OKAY"
                    : "UNKNOWN"))
    );
    if (status > 0) {
        buf_ptr += status;
        buf_len -= status;
    }

#define APPEND(bufptr, buflen, key, value)                                     \
    if ((buflen > 0) && (strlen(value) > 0)) {                                 \
        status = snprintf(bufptr, buflen, ", %s = %s", key, value);            \
        if (status > 0) {                                                      \
            bufptr += status;                                                  \
            buflen -= status;                                                  \
        }                                                                      \
    }
    APPEND(buf_ptr, buf_len, "host", n->host);
    APPEND(buf_ptr, buf_len, "plugin", n->plugin);
    APPEND(buf_ptr, buf_len, "plugin_instance", n->plugin_instance);
    APPEND(buf_ptr, buf_len, "type", n->type);
    APPEND(buf_ptr, buf_len, "type_instance", n->type_instance);
    APPEND(buf_ptr, buf_len, "message", n->message);

    buf[sizeof(buf) - 1] = '\0';

    pthread_mutex_lock(&greeting_lock);

    fprintf(stdout, "%s %s\n", greeting, buf);
    fflush(stdout);

    pthread_mutex_unlock(&greeting_lock);

    return 0;
}

void module_register(void) {
    plugin_register_init("notify_telegram", notify_telegram_init);
    plugin_register_shutdown("notify_telegram", notify_telegram_shutdown);
    plugin_register_config("notify_telegram", notify_telegram_config, config_keys, config_keys_num);
    plugin_register_notification("notify_telegram", notify_telegram_notification, /* user_data = */ NULL);
}
