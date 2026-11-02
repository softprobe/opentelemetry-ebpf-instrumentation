// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <maps/softprobe_request_context.h>

static __always_inline void softprobe_store_request_context(connection_info_t *connection,
                                                            tp_info_t *tp) {
    if (!connection || !tp) {
        return;
    }

    connection_info_t client_connection = *connection;
    sort_connection_info(&client_connection);

    softprobe_request_context_key_t key = {};
    __builtin_memcpy(key.client_addr, client_connection.s_addr, sizeof(key.client_addr));
    key.client_port = client_connection.s_port;

    softprobe_request_context_t value = {.tp = *tp, .updated_at_ns = bpf_ktime_get_ns()};
    bpf_map_update_elem(&sp_request_ctx_v1, &key, &value, BPF_ANY);
}
