/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.util;

import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;

public class NettyChannelExtractor {

  // Called always by reflection, that's why unused
  @SuppressWarnings("unused")
  public static Connection extractConnectionFromChannelHandlerContext(Object ctx) {
    Connection c = null;
    try {
      Method channelMethod = ctx.getClass().getMethod("channel");
      channelMethod.setAccessible(true);
      Object channel = channelMethod.invoke(ctx);

      Method localAddressMethod = channel.getClass().getMethod("localAddress");
      localAddressMethod.setAccessible(true);
      InetSocketAddress localAddress = (InetSocketAddress) localAddressMethod.invoke(channel);

      Method remoteAddressMethod = channel.getClass().getMethod("remoteAddress");
      remoteAddressMethod.setAccessible(true);
      InetSocketAddress remoteAddress = (InetSocketAddress) remoteAddressMethod.invoke(channel);

      if (SSLStorage.debugOn) {
        System.err.println("[NettyChannelExtractor] Netty channel localAddress: " + localAddress);
        System.err.println("[NettyChannelExtractor] Netty channel remoteAddress: " + remoteAddress);
      }
      c =
          new Connection(
              localAddress.getAddress(),
              localAddress.getPort(),
              remoteAddress.getAddress(),
              remoteAddress.getPort());
    } catch (Exception x) {
      System.err.println("[NettyChannelExtractor] Failed to extract netty channel data " + x);
    }

    return c;
  }

  @SuppressWarnings("unused")
  public static Connection extractConnectionFromIOSession(Object session) {
    Connection c = null;
    try {
      Method localAddressMethod = session.getClass().getMethod("getLocalAddress");
      localAddressMethod.setAccessible(true);
      Object localObj = localAddressMethod.invoke(session);

      Method remoteAddressMethod = session.getClass().getMethod("getRemoteAddress");
      remoteAddressMethod.setAccessible(true);
      Object remoteObj = remoteAddressMethod.invoke(session);

      if (localObj instanceof InetSocketAddress && remoteObj instanceof InetSocketAddress) {
        InetSocketAddress localAddress = (InetSocketAddress) localObj;
        InetSocketAddress remoteAddress = (InetSocketAddress) remoteObj;
        if (localAddress.getAddress() != null && remoteAddress.getAddress() != null) {
          c =
              new Connection(
                  localAddress.getAddress(),
                  localAddress.getPort(),
                  remoteAddress.getAddress(),
                  remoteAddress.getPort());
        }
      }
    } catch (Exception x) {
      if (SSLStorage.debugOn) {
        System.err.println("[NettyChannelExtractor] Failed to extract IOSession data " + x);
      }
    }
    return c;
  }
}
