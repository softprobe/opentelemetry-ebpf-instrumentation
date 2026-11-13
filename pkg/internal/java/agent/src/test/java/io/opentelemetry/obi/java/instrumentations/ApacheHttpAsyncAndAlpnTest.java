/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import io.opentelemetry.obi.java.instrumentations.util.NettyChannelExtractor;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import javax.net.ssl.SSLParameters;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ApacheHttpAsyncAndAlpnTest {

  static class MockIOSession {
    private final SocketAddress local;
    private final SocketAddress remote;

    MockIOSession(SocketAddress local, SocketAddress remote) {
      this.local = local;
      this.remote = remote;
    }

    public SocketAddress getLocalAddress() {
      return local;
    }

    public SocketAddress getRemoteAddress() {
      return remote;
    }
  }

  @AfterEach
  void reset() {
    SSLStorage.preferHttp1Alpn = false;
  }

  @Test
  void extractsConnectionFromIOSession() throws Exception {
    InetSocketAddress local = new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 44123);
    InetSocketAddress remote = new InetSocketAddress(InetAddress.getByName("104.21.10.20"), 443);
    Connection c =
        NettyChannelExtractor.extractConnectionFromIOSession(new MockIOSession(local, remote));
    assertNotNull(c);
    assertEquals(local.getAddress(), c.getLocalAddress());
    assertEquals(44123, c.getLocalPort());
    assertEquals(remote.getAddress(), c.getRemoteAddress());
    assertEquals(443, c.getRemotePort());
  }

  @Test
  void filtersH2OnlyWhenHttp1FallbackExists() {
    String[] mixed = new String[] {"h2", "http/1.1"};
    assertArrayEquals(new String[] {"http/1.1"}, SSLStorage.filterHttp1AlpnProtocols(mixed));

    String[] grpcOnly = new String[] {"h2"};
    assertSame(grpcOnly, SSLStorage.filterHttp1AlpnProtocols(grpcOnly));

    String[] http1Only = new String[] {"http/1.1"};
    assertSame(http1Only, SSLStorage.filterHttp1AlpnProtocols(http1Only));
  }

  @Test
  void appliesAlpnPreferenceToSSLParametersWhenEnabled() throws Exception {
    SSLParameters params = new SSLParameters();
    java.lang.reflect.Method setMethod =
        SSLParameters.class.getMethod("setApplicationProtocols", String[].class);
    java.lang.reflect.Method getMethod = SSLParameters.class.getMethod("getApplicationProtocols");
    setMethod.invoke(params, (Object) new String[] {"h2", "http/1.1"});

    SSLStorage.preferHttp1Alpn = false;
    SSLStorage.applyHttp1AlpnPreference(params);
    assertArrayEquals(new String[] {"h2", "http/1.1"}, (String[]) getMethod.invoke(params));

    SSLStorage.preferHttp1Alpn = true;
    SSLStorage.applyHttp1AlpnPreference(params);
    assertArrayEquals(new String[] {"http/1.1"}, (String[]) getMethod.invoke(params));
    assertTrue(SSLAlpnPreferenceInst.matches(javax.net.ssl.SSLSocket.class));
  }
}
