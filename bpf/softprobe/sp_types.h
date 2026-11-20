// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

typedef struct sp_orig_dst {
    u8 ip[16];
    u16 port;
    u16 family;
    u32 pid;
} sp_orig_dst_t;

typedef struct sp_tuple_key {
    u16 client_port;
    u16 proxy_port;
} sp_tuple_key_t;

typedef struct sp_bypass_key {
    u16 client_port;
    u16 target_port;
} sp_bypass_key_t;

typedef struct sp_write_ctx_event {
    u64 sock_cookie;
    u64 byte_offset;
    u32 payload_len;
    u32 pid;
    u32 tid;
    u32 flags;
    u8 trace_id[16];
    u8 span_id[8];
} sp_write_ctx_event_t;

const sp_write_ctx_event_t *sp_write_ctx_event__unused __attribute__((unused));
