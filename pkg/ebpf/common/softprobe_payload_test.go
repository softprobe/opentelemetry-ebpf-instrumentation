// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func TestCaptureTCPPayloadsCopiesWireBuffers(t *testing.T) {
	requestPayload := []byte("postgres request")
	responsePayload := []byte("postgres response")
	requestBuffer := largebuf.NewLargeBufferFrom(requestPayload)
	responseBuffer := largebuf.NewLargeBufferFrom(responsePayload)
	span := request.Span{}

	captureTCPPayloads(&span, requestBuffer, responseBuffer)
	requestBuffer.UnsafeView()[0] = 'P'
	responseBuffer.UnsafeView()[0] = 'P'

	require.Equal(t, []byte("postgres request"), span.SoftprobeRequestPayload)
	require.Equal(t, []byte("postgres response"), span.SoftprobeResponsePayload)
}
