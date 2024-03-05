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

#include <curl/curl.h>
#include <yajl/yajl_parse.h>
#if HAVE_YAJL_YAJL_VERSION_H
#include <yajl/yajl_version.h>
#endif

#if defined(YAJL_MAJOR) && (YAJL_MAJOR > 1)
#define HAVE_YAJL_V2 1
#endif

#define MAX_BUF_SIZE 1024
#define MAX_URL_SIZE 128
#define MAX_PARAMS_SIZE 2048
#define MAX_INPUT_MESSAGES_COUNT 30

#define PARSE_OK 1
#define PARSE_FAIL 0

struct response_buffer_t {
    char *response;
    size_t size;
};

struct parse_context_t {
    int depth;
    bool inside_key_ok;
    bool inside_key_update_id;
    bool inside_key_message;
    bool inside_key_message_chat;
    bool inside_key_message_chat_id;
    bool ok;
    char *max_update_id;
    int chat_id_count;
    char *chat_id[MAX_INPUT_MESSAGES_COUNT];
};

#if HAVE_YAJL_V2
typedef size_t yajl_len_t;
#else
typedef unsigned int yajl_len_t;
#endif

static const char *config_keys[] = {"BotToken", "ProxyURL", "RecipientChatID"};
static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);

static char *bot_token;
static char *proxy_url;
static char **recipients;
static int recipients_len;

static pthread_mutex_t telegram_lock = PTHREAD_MUTEX_INITIALIZER;

static size_t tg_curl_write_callback(void *data, size_t size, size_t nmemb, void *user_data)
{
    size_t realsize = size * nmemb;
    struct response_buffer_t *buf = (struct response_buffer_t *)user_data;
    char *ptr = realloc(buf->response, buf->size + realsize + 1);
    if (!ptr) {
        ERROR("notify_telegram: realloc failed.");
        return 0;
    }

    buf->response = ptr;
    memcpy(&(buf->response[buf->size]), data, realsize);
    buf->size += realsize;
    buf->response[buf->size] = 0;

    return realsize;
}

static int tg_parse_bool_callback(void *ctx, int bool_val) {
    struct parse_context_t *parse_context = (struct parse_context_t *)ctx;
    if (parse_context->inside_key_ok) {
        parse_context->ok = bool_val;
        parse_context->inside_key_ok = false;
    }

    return PARSE_OK;
}

static int tg_parse_number_callback(void *ctx, const char *number, yajl_len_t number_len) {
    struct parse_context_t *parse_context = (struct parse_context_t *)ctx;

    if (parse_context->inside_key_update_id) {
        if (parse_context->max_update_id == NULL) {
            parse_context->max_update_id = strndup(number, number_len);
            if (parse_context->max_update_id == NULL) {
                ERROR("notify_telegram: strndup failed.");
                return PARSE_FAIL;
            }
        } else {
            char number_buffer[number_len + 1];
            memcpy(number_buffer, number, number_len);
            number_buffer[number_len] = '\0';

            if (strtoull(number_buffer, NULL, 10) > strtoull(parse_context->max_update_id, NULL, 10)) {
                parse_context->max_update_id = strndup(number, number_len);
                if (parse_context->max_update_id == NULL) {
                    ERROR("notify_telegram: strndup failed.");
                    return PARSE_FAIL;
                }
            }
        }
        parse_context->inside_key_update_id = false;
    } else if (parse_context->inside_key_message_chat_id) {
        parse_context->chat_id[parse_context->chat_id_count] = strndup(number, number_len);
        if (parse_context->chat_id == NULL) {
            ERROR("notify_telegram: strndup failed.");
            return PARSE_FAIL;
        }
        parse_context->chat_id_count++;
        parse_context->inside_key_message_chat_id = false;
    }

    return PARSE_OK;
}

static int tg_parse_start_map_callback(void *ctx) {
    struct parse_context_t *parse_context = (struct parse_context_t *)ctx;
    parse_context->depth++;

    return PARSE_OK;
}

static int tg_parse_map_key_callback(void *ctx, const unsigned char *key, yajl_len_t key_len) {
    struct parse_context_t *parse_context = (struct parse_context_t *)ctx;
    char key_buffer[key_len + 1];
    memcpy(key_buffer, key, key_len);
    key_buffer[sizeof(key_buffer) - 1] = '\0';

    if (parse_context->depth == 1) {
        parse_context->inside_key_ok = false;
        if (!strcmp(key_buffer, "ok")) {
            parse_context->inside_key_ok = true;
        }
    } else if (parse_context->depth == 2) {
        parse_context->inside_key_update_id = false;
        parse_context->inside_key_message = false;
        parse_context->inside_key_message_chat = false;
        parse_context->inside_key_message_chat_id = false;
        if (!strcmp(key_buffer, "update_id")) {
            parse_context->inside_key_update_id = true;
        } else if (!strcmp(key_buffer, "message")) {
            parse_context->inside_key_message = true;
        }
    } else if (parse_context->depth == 3) {
        parse_context->inside_key_message_chat = false;
        parse_context->inside_key_message_chat_id = false;
        if (parse_context->inside_key_message && !strcmp(key_buffer, "chat")) {
            parse_context->inside_key_message_chat = true;
        }
    } else if (parse_context->depth == 4) {
        parse_context->inside_key_message_chat_id = false;
        if (parse_context->inside_key_message_chat && !strcmp(key_buffer, "id")) {
            parse_context->inside_key_message_chat_id = true;
        }
    }

    return PARSE_OK;
}

static int tg_parse_end_map_callback(void *ctx) {
    struct parse_context_t *parse_context = (struct parse_context_t *)ctx;
    parse_context->depth--;

    return PARSE_OK;
}

static void free_parse_context(struct parse_context_t *parse_context) {
    if (parse_context) {
        sfree(parse_context->max_update_id);
        for (int i=0; i<parse_context->chat_id_count; ++i) {
            sfree(parse_context->chat_id[i]);
        }
    }
}

static int notify_telegram_read(void) {
    struct response_buffer_t buf = {0};
    char url[MAX_URL_SIZE] = "";
    if (proxy_url) {
        snprintf(url, MAX_URL_SIZE, "%s%s/getUpdates", proxy_url, bot_token);
    } else {
        snprintf(url, MAX_URL_SIZE, "https://api.telegram.org/bot%s/getUpdates", bot_token);
    }
    char params[MAX_PARAMS_SIZE] = "";
    snprintf(params, MAX_PARAMS_SIZE, "limit=%d&allowed_updates=[\"message\"]", MAX_INPUT_MESSAGES_COUNT);
    CURL *handle = curl_easy_init();
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, params);
    curl_easy_setopt(handle, CURLOPT_URL, url);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, tg_curl_write_callback);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, (void *)&buf);
    pthread_mutex_lock(&telegram_lock);
    CURLcode response_code = curl_easy_perform(handle);
    pthread_mutex_unlock(&telegram_lock);
    curl_easy_cleanup(handle);
    DEBUG("notify_telegram: curl response = %s", buf.response);
    if (response_code != CURLE_OK) {
        ERROR("notify_telegram: curl_easy_perform failed.");
        sfree(buf.response);
        return -1;
    }

    struct parse_context_t parse_context = {0};
    yajl_callbacks ycallbacks = {
        NULL,
        tg_parse_bool_callback,
        NULL,
        NULL,
        tg_parse_number_callback,
        NULL,
        tg_parse_start_map_callback,
        tg_parse_map_key_callback,
        tg_parse_end_map_callback,
        NULL,
        NULL
    };
    yajl_handle yajl_handler = yajl_alloc(
        &ycallbacks,
#if HAVE_YAJL_V2
        NULL,
#else
        NULL, NULL,
#endif
        (void *)&parse_context
    );
    if (yajl_handler == NULL) {
        ERROR("notify_telegram: yajl_alloc failed.");
        sfree(buf.response);
        return -1;
    }
    yajl_status status = yajl_parse(yajl_handler, (unsigned char *)buf.response, buf.size);
    sfree(buf.response);
    if (status != yajl_status_ok) {
        ERROR("notify_telegram: yajl_parse failed.");
        free_parse_context(&parse_context);
        return -1;
    }
    if (!parse_context.ok) {
        ERROR("notify_telegram: not ok response from telegram api.");
        free_parse_context(&parse_context);
        return -1;
    }

    if (parse_context.chat_id_count > 0 && parse_context.max_update_id != NULL) {
        const char *CONFIG_HELP_TEXT_TEMPLATE =
            "Here is the collectd configuration with your chat id:\n"
            "```\n"
            "<Plugin notify_telegram>\n"
            "    BotToken \"telegram-bot-token\"\n"
            "    ProxyURL \"https://api\\.telegram\\.org/bot\"\n"
            "    RecipientChatID \"%s\"\n"
            "</Plugin>\n"
            "```\n"
            "If you use Local Bot API Server, set `ProxyURL` to your server URL\n"
            "Read more: https://core\\.telegram\\.org/bots/api\\#using\\-a\\-local\\-bot\\-api\\-server"
        ;
        if (proxy_url) {
            snprintf(url, MAX_URL_SIZE, "%s%s/sendMessage", proxy_url, bot_token);
        } else {
            snprintf(url, MAX_URL_SIZE, "https://api.telegram.org/bot%s/sendMessage", bot_token);
        }
        struct response_buffer_t help_response_buf = {0};
        handle = curl_easy_init();
        curl_easy_setopt(handle, CURLOPT_URL, url);
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, tg_curl_write_callback);
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, (void *)&help_response_buf);
        char help_text[MAX_BUF_SIZE] = "";
        for (int i=0; i<parse_context.chat_id_count; ++i) {
            snprintf(help_text, MAX_BUF_SIZE, CONFIG_HELP_TEXT_TEMPLATE, parse_context.chat_id[i]);
            snprintf(params, MAX_PARAMS_SIZE, "parse_mode=MarkdownV2&chat_id=%s&text=%s", parse_context.chat_id[i], help_text);
            curl_easy_setopt(handle, CURLOPT_POSTFIELDS, params);
            pthread_mutex_lock(&telegram_lock);
            response_code = curl_easy_perform(handle);
            pthread_mutex_unlock(&telegram_lock);
            if (response_code != CURLE_OK) {
                ERROR("notify_telegram: curl_easy_perform failed.");
                curl_easy_cleanup(handle);
                free_parse_context(&parse_context);
                sfree(help_response_buf.response);
                return -1;
            }
        }
        DEBUG("notify_telegram: curl response = %s", help_response_buf.response);
        sfree(help_response_buf.response);
        curl_easy_cleanup(handle);

        if (proxy_url) {
            snprintf(url, MAX_URL_SIZE, "%s%s/getUpdates", proxy_url, bot_token);
        } else {
            snprintf(url, MAX_URL_SIZE, "https://api.telegram.org/bot%s/getUpdates", bot_token);
        }
        snprintf(params, MAX_PARAMS_SIZE, "offset=%llu", 1ULL + strtoull(parse_context.max_update_id, NULL, 10));
        free_parse_context(&parse_context);
        struct response_buffer_t update_response_buf = {0};
        handle = curl_easy_init();
        curl_easy_setopt(handle, CURLOPT_POSTFIELDS, params);
        curl_easy_setopt(handle, CURLOPT_URL, url);
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, tg_curl_write_callback);
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, (void *)&update_response_buf);
        pthread_mutex_lock(&telegram_lock);
        response_code = curl_easy_perform(handle);
        pthread_mutex_unlock(&telegram_lock);
        curl_easy_cleanup(handle);
        DEBUG("notify_telegram: curl response = %s", update_response_buf.response);
        sfree(update_response_buf.response);
        if (response_code != CURLE_OK) {
            ERROR("notify_telegram: curl_easy_perform failed.");
            return -1;
        }
    } else {
        free_parse_context(&parse_context);
    }

    return 0;
}

static int notify_telegram_init(void) {
    curl_global_init(CURL_GLOBAL_SSL);

    return notify_telegram_read();
}

static int notify_telegram_shutdown(void) {
    curl_global_cleanup();

    return 0;
}

static int notify_telegram_config(const char *key, const char *value) {
    if (strcasecmp(key, "RecipientChatID") == 0) {
        char **tmp;
        tmp = realloc(recipients, (recipients_len + 1) * sizeof(char *));
        if (tmp == NULL) {
            ERROR("notify_telegram: realloc failed.");
            return -1;
        }
        recipients = tmp;
        recipients[recipients_len] = strdup(value);
        if (recipients[recipients_len] == NULL) {
            ERROR("notify_telegram: strdup failed.");
            return -1;
        }
        recipients_len++;
    } else if (strcasecmp(key, "BotToken") == 0) {
        sfree(bot_token);
        bot_token = strdup(value);
        if (bot_token == NULL) {
            ERROR("notify_telegram: strdup failed.");
            return -1;
        }
    } else if (strcasecmp(key, "ProxyURL") == 0) {
        sfree(proxy_url);
        proxy_url = strdup(value);
        if (proxy_url == NULL) {
            ERROR("notify_telegram: strdup failed.");
            return -1;
        }
    } else {
        ERROR("notify_telegram: unknown config key.");
        return -1;
    }
    return 0;
}

static int notify_telegram_notification(const notification_t *n, user_data_t __attribute__((unused)) * user_data) {
    char buf[MAX_BUF_SIZE] = "";
    char *buf_ptr = buf;
    int buf_len = sizeof(buf);
    int status;

    status = snprintf(
        buf_ptr, buf_len, "<b>Notification:</b>\nseverity = %s",
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
        status = snprintf(bufptr, buflen, ",\n%s = %s", key, value);            \
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

    char url[MAX_URL_SIZE] = "";
    if (proxy_url) {
        snprintf(url, MAX_URL_SIZE, "%s%s/sendMessage", proxy_url, bot_token);
    } else {
        snprintf(url, MAX_URL_SIZE, "https://api.telegram.org/bot%s/sendMessage", bot_token);
    }
    struct response_buffer_t notify_response_buf = {0};
    CURL *handle = curl_easy_init();
    curl_easy_setopt(handle, CURLOPT_URL, url);
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, tg_curl_write_callback);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, (void *)&notify_response_buf);
    char params[MAX_PARAMS_SIZE] = "";
    for (int i=0; i<recipients_len; ++i) {
        snprintf(params, MAX_PARAMS_SIZE, "parse_mode=HTML&chat_id=%s&text=%s", recipients[i], buf);
        curl_easy_setopt(handle, CURLOPT_POSTFIELDS, params);
        pthread_mutex_lock(&telegram_lock);
        CURLcode response_code = curl_easy_perform(handle);
        pthread_mutex_unlock(&telegram_lock);
        if (response_code != CURLE_OK) {
            ERROR("notify_telegram: curl_easy_perform failed.");
            curl_easy_cleanup(handle);
            sfree(notify_response_buf.response);
            return -1;
        }
    }
    DEBUG("notify_telegram: curl response = %s", notify_response_buf.response);
    sfree(notify_response_buf.response);
    curl_easy_cleanup(handle);

    return 0;
}

void module_register(void) {
    plugin_register_init("notify_telegram", notify_telegram_init);
    plugin_register_shutdown("notify_telegram", notify_telegram_shutdown);
    plugin_register_config("notify_telegram", notify_telegram_config, config_keys, config_keys_num);
    plugin_register_read("notify_telegram", notify_telegram_read);
    plugin_register_notification("notify_telegram", notify_telegram_notification, /* user_data = */ NULL);
}
