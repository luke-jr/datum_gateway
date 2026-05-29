/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of OCEAN's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2026 Bitcoin Ocean, LLC & Luke Dashjr
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>
#include <jansson.h>

#include "datum_conf.h"
#include "datum_logger.h"
#include "datum_rsk.h"
#include "datum_utils.h"

pthread_rwlock_t rsk_commitment_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static char rsk_commitment_hex_unterminated[RSK_COMMITMENT_SIZE * 2];
static uint8_t rsk_target[RSK_TARGET_SIZE];

// NOTE: datum_rsk_buf uses unsigned int lengths because this is < 2^16
#define DATUM_RSK_BUF_SZ  0x200

struct datum_rsk_buf {
	unsigned int offset;
	unsigned int len;
	uint8_t buf[DATUM_RSK_BUF_SZ];
};

struct datum_rsk_state {
	CURLM *curlm;
	CURL *curl;
	char curl_error[CURL_ERROR_SIZE];
	bool standoff;
	uint64_t next_update_mono_ms;
	struct datum_rsk_buf recv_buf;
	struct datum_rsk_buf send_buf;
};

#define DATUM_RSK_CURL_ERROR_FMT " (error=%llu %s%s%s)"
#define DATUM_RSK_CURL_ERROR_VARS_C (unsigned long long)cresult, curl_easy_strerror(cresult), state->curl_error[0] ? ": " : "", state->curl_error
#define DATUM_RSK_CURL_ERROR_VARS_M (unsigned long long)mresult, curl_multi_strerror(mresult), state->curl_error[0] ? ": " : "", state->curl_error

static
CURL *datum_rsk_create_curl(const global_config_t * const cfg, struct datum_rsk_state * const state) {
	CURLcode cresult;
	CURLMcode mresult;
	CURL * const curl = curl_easy_init();
	
	state->curl_error[0] = '\0';
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, state->curl_error);
	
	cresult = curl_easy_setopt(curl, CURLOPT_URL, cfg->rsk_wsurl);
	if (cresult != CURLE_OK) {
		DLOG_ERROR("%s: curl_easy_setopt CURLOPT_URL failed" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_C);
		curl_easy_cleanup(curl);
		return NULL;
	}
	
	cresult = curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L);
	if (cresult != CURLE_OK) {
		DLOG_ERROR("%s: curl_easy_setopt CURLOPT_CONNECT_ONLY failed" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_C);
		curl_easy_cleanup(curl);
		return NULL;
	}
	
	mresult = curl_multi_add_handle(state->curlm, curl);
	if (mresult != CURLM_OK) {
		DLOG_ERROR("%s: curl_multi_add_handle failed" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_M);
		curl_easy_cleanup(curl);
		return NULL;
	}
	
	return curl;
}

static
void datum_rsk_disconnect(struct datum_rsk_state * const state) {
	curl_multi_remove_handle(state->curlm, state->curl);
	size_t sent;
	curl_ws_send(state->curl, "", 0, &sent, 0, CURLWS_CLOSE);
	curl_easy_cleanup(state->curl);
	state->curl = NULL;
}

static
void datum_rsk_handle_message(struct datum_rsk_state * const state) {
	const json_t *j;
	json_error_t jerr;
	const json_t * const jmsg = json_loadb((char*)state->recv_buf.buf, state->recv_buf.len, 0, &jerr);
	if (!jmsg) {
		DLOG_ERROR("%s: json_loadb failed (error=%s)", __func__, jerr.text);
		datum_rsk_disconnect(state);
		return;
	}
	state->recv_buf.len = 0;
	
	j = json_object_get(jmsg, "method");
	if (j) {
		if (0 == strcmp(json_string_value(j), "eth_subscription")) {
			// New block, update work ASAP
			state->next_update_mono_ms = 0;
		}
		return;
	}
	j = json_object_get(jmsg, "id");
	if (json_integer_value(j) == 1) {
		j = json_object_get(jmsg, "result");
		if (json_array_size(j) < 3) {
			DLOG_ERROR("%s: Invalid getwork result (%s)", __func__, "fewer than 3 array items");
			return;
		}
		
		const json_t * const j_pow_hash = json_array_get(j, 0);
		if (json_string_length(j_pow_hash) != RSK_COMMITMENT_SIZE * 2) {
			DLOG_ERROR("%s: Invalid getwork result (%s)", __func__, "wrong PoW hash size");
			return;
		}
		const char * const pow_hash_hex = json_string_value(j_pow_hash);
		if (!is_all_hex(pow_hash_hex, RSK_COMMITMENT_SIZE * 2)) {
			DLOG_ERROR("%s: Invalid getwork result (%s)", __func__, "non-hex PoW hash");
			return;
		}
		
		const json_t * const j_target = json_array_get(j, 2);
		uint8_t rsk_target_new[RSK_TARGET_SIZE];
		if (!hex_to_bin_checked(json_string_value(j_target), rsk_target_new)) {
			DLOG_ERROR("%s: Invalid getwork result (%s)", __func__, "invalid target");
			return;
		}
		
		pthread_rwlock_wrlock(&rsk_commitment_rwlock);
		memcpy(rsk_commitment_hex_unterminated, pow_hash_hex, RSK_COMMITMENT_SIZE);
		memcpy(rsk_target, rsk_target_new, RSK_TARGET_SIZE);
		pthread_rwlock_unlock(&rsk_commitment_rwlock);
	}
}

static
bool datum_rsk_handle_recv(struct datum_rsk_state * const state) {
	CURLcode cresult;
	
	size_t rlen;
	const struct curl_ws_frame *meta;
	cresult = curl_ws_recv(state->curl, &state->recv_buf.buf[state->recv_buf.len], DATUM_RSK_BUF_SZ - state->recv_buf.len, &rlen, &meta);
	if (cresult != CURLE_OK) {
		if (cresult == CURLE_AGAIN) return true;
		
		DLOG_ERROR("%s: curl_ws_recv failed" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_C);
		return false;
	}
	
	assert(rlen < DATUM_RSK_BUF_SZ - state->recv_buf.len);
	state->recv_buf.len += rlen;
	if (meta->bytesleft == 0) {
		datum_rsk_handle_message(state);
	} else if (meta->bytesleft > DATUM_RSK_BUF_SZ - state->recv_buf.len) {
		DLOG_ERROR("%s: receive buffer overflow (%zu bytes in %zu-byte buffer, %llu bytes remaining)", __func__, (size_t)state->recv_buf.len, (size_t)DATUM_RSK_BUF_SZ, (unsigned long long)meta->bytesleft);
		datum_rsk_disconnect(state);
		return false;
	}
	
	return true;
}

static inline
bool datum_rsk_handle_send(struct datum_rsk_state * const state) {
	CURLcode cresult;
	
	size_t sent;
	cresult = curl_ws_send(state->curl, &state->send_buf.buf[state->send_buf.offset], state->send_buf.len, &sent, 0, CURLWS_TEXT);
	if (cresult != CURLE_OK) {
		if (cresult == CURLE_AGAIN) return true;
		
		DLOG_ERROR("%s: curl_ws_send failed" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_C);
		datum_rsk_disconnect(state);
		return false;
	}
	state->send_buf.offset += sent;
	state->send_buf.len -= sent;
	return true;
}

static
void datum_rsk_wait(struct datum_rsk_state * const state, int timeout_ms) {
	CURLMcode mresult;
	
	if (state->curl) {
		const uint64_t start_mono_ms = monotonic_time_millis();
		datum_update_timeout(&timeout_ms, state->next_update_mono_ms, start_mono_ms);
	}
	
	mresult = curl_multi_poll(state->curlm, NULL, 0, timeout_ms, NULL);
	if (mresult != CURLM_OK) {
		DLOG_ERROR("%s: curl_multi_poll failed" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_M);
		sleep(1);
	}
}

// CAUTION: Overwrites any previous queued send! Websocket is packet-based, so we can only send one at a time.
static inline
void datum_rsk_queue_send(struct datum_rsk_state * const state, const char * const msg, const size_t msg_len) {
	assert(msg_len <= DATUM_RSK_BUF_SZ);
	static_assert(DATUM_RSK_BUF_SZ < UINT_MAX);
	state->send_buf.offset = 0;
	state->send_buf.len = (unsigned int)msg_len;
	memcpy(state->send_buf.buf, msg, msg_len);
}

static
void datum_rsk_process(const global_config_t * const cfg, struct datum_rsk_state * const state) {
	CURLcode cresult;
	CURLMcode mresult;
	
	if (!state->curl) state->curl = datum_rsk_create_curl(cfg, state->curlm);
	
	int still_connecting;
	mresult = curl_multi_perform(state->curlm, &still_connecting);
	if (mresult != CURLM_OK) {
		DLOG_ERROR("%s: curl_multi_perform failed" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_M);
	}
	
	if (still_connecting) {
		return;
	}
	
	int msgs_in_queue;
	CURLMsg *msg;
	while ( (msg = curl_multi_info_read(state->curlm, &msgs_in_queue)) ) {
		switch (msg->msg) {
			case CURLMSG_DONE:
			{
				cresult = msg->data.result;
				if (msg->data.result == CURLE_OK) {
					// Connected, so subscribe
					static const char sub_req[] = "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"eth_subscribe\",\"params\":[\"newHeads\"]}";
					datum_rsk_queue_send(state, sub_req, sizeof(sub_req) - 1);
					state->next_update_mono_ms = 0;
					state->recv_buf.len = 0;
				} else {
					DLOG_ERROR("%s: Error connecting to Rootstock node" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_C);
					sleep(1);
				}
				break;
			}
			default: ;
		}
	}
	
	if (state->curl) {
		if (datum_rsk_handle_recv(state)) {
			if (state->send_buf.len == 0) {
				const uint64_t now_mono_ms = monotonic_time_millis();
				if (now_mono_ms >= state->next_update_mono_ms) {
					static const char getwork_req[] = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"mnr_getWork\",\"params\":[]}";
					datum_rsk_queue_send(state, getwork_req, sizeof(getwork_req) - 1);
					state->next_update_mono_ms = now_mono_ms + ((uint64_t)cfg->rsk_work_update_seconds * 1000);
				}
			}
			
			if (state->send_buf.len > 0) {
				if (!datum_rsk_handle_send(state)) {
					goto curl_err;
				}
			}
			
			state->standoff = false;
		} else {
curl_err:
			if (state->standoff) sleep(1);
			state->standoff = true;
		}
	}
}

static
void *datum_rsk_thread(void * const p) {
	const global_config_t * const cfg = p;
	
	struct datum_rsk_state state = {
		.curlm = curl_multi_init(),
	};
	if (!state.curlm) {
		DLOG_ERROR("%s: curl_multi_init failed; Rootstock functionality disabled", __func__);
		return NULL;
	}
	
	while (1) {
		datum_rsk_process(cfg, &state);
		datum_rsk_wait(&state, INT_MAX);
	}
}

bool datum_rsk_init(const global_config_t * const cfg) {
	pthread_t pthread_datum_rsk_thread;
	int result = pthread_create(&pthread_datum_rsk_thread, NULL, datum_rsk_thread, NULL);

	if (result != 0) {
		DLOG_ERROR("%s: pthread_create failed with code %d (%s); Rootstock functionality disabled", __func__, result, strerror(result));
		return false;
	}

	return true;
}

void datum_rsk_get_current_work(char * const out_rsk_commitment_hex_unterminated, uint8_t * const out_target) {
	pthread_rwlock_rdlock(&rsk_commitment_rwlock);
	memcpy(out_rsk_commitment_hex_unterminated, rsk_commitment_hex_unterminated, RSK_COMMITMENT_SIZE);
	memcpy(out_target, rsk_target, RSK_TARGET_SIZE);
	pthread_rwlock_unlock(&rsk_commitment_rwlock);
}
