/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Modifier;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.nio.protocol.HttpAsyncRequestProducer;
import org.junit.jupiter.api.Test;

class ApacheHttpAsyncClientInstTest {
  @Test
  void matchesHttpAsyncRequestProducerImplementations() {
    assertTrue(ApacheHttpAsyncClientInst.matches(TestProducer.class));
    assertFalse(ApacheHttpAsyncClientInst.matches(Object.class));
  }

  @Test
  void matchesCloseableApacheAsyncClientBase() {
    assertTrue(ApacheHttpAsyncClientInst.matches(TestAsyncClient.class));
  }

  @Test
  void exposesProducerTrackingToInlinedAdvice() throws NoSuchMethodException {
    assertTrue(
        Modifier.isPublic(
            ApacheHttpAsyncClientInst.class
                .getDeclaredMethod("trackProducer", Object.class, long.class)
                .getModifiers()));
    assertTrue(
        Modifier.isPublic(
            ApacheHttpAsyncClientInst.class
                .getDeclaredMethod("producerThreadId", Object.class)
                .getModifiers()));
    assertTrue(
        Modifier.isPublic(
            ApacheHttpAsyncClientInst.class
                .getDeclaredMethod("removeProducer", Object.class)
                .getModifiers()));
    assertTrue(
        Modifier.isPublic(
            ApacheHttpAsyncClientInst.class
                .getDeclaredMethod("handoffProducerContext", Object.class, String.class)
                .getModifiers()));
  }

  @Test
  void storesAndRemovesRequestThreadByProducerIdentity() {
    TestProducer producer = new TestProducer();
    ApacheHttpAsyncClientInst.trackProducer(producer, 1234L);

    assertEquals(1234L, ApacheHttpAsyncClientInst.producerThreadId(producer));

    ApacheHttpAsyncClientInst.removeProducer(producer);
    assertNull(ApacheHttpAsyncClientInst.producerThreadId(producer));
  }

  private static final class TestProducer implements HttpAsyncRequestProducer {}

  private static final class TestAsyncClient extends CloseableHttpAsyncClient {}
}
