// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/tp_info.h>

typedef struct softprobe_request_context_key {
    u8 client_addr[16];
    u16 client_port;
    u8 _pad[2];
} softprobe_request_context_key_t;

typedef struct softprobe_request_context {
    tp_info_t tp;
    u64 updated_at_ns;
} softprobe_request_context_t;

// This versioned pinned map hands OBI's trace context to local protocol
// gateways. It is keyed by the client side of a connection and refreshed for
// each observed client request, including each SQL statement on pooled DB
// connections.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, softprobe_request_context_key_t);
    __type(value, softprobe_request_context_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sp_request_ctx_v1 SEC(".maps");
