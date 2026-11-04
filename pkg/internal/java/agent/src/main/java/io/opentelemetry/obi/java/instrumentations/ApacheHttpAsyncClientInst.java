/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.Agent;
import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class ApacheHttpAsyncClientInst {
  private static final String HTTP_ASYNC_REQUEST_PRODUCER_CLASS =
      "org.apache.http.nio.protocol.HttpAsyncRequestProducer";
  private static final String CLOSEABLE_HTTP_ASYNC_CLIENT_CLASS =
      "org.apache.http.impl.nio.client.CloseableHttpAsyncClient";
  private static final String INTERNAL_HTTP_ASYNC_CLIENT_CLASS =
      "org.apache.http.impl.nio.client.InternalHttpAsyncClient";
  private static final String MINIMAL_HTTP_ASYNC_CLIENT_CLASS =
      "org.apache.http.impl.nio.client.MinimalHttpAsyncClient";

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.named(INTERNAL_HTTP_ASYNC_CLIENT_CLASS)
        .or(ElementMatchers.named(MINIMAL_HTTP_ASYNC_CLIENT_CLASS))
        .or(ElementMatchers.named(CLOSEABLE_HTTP_ASYNC_CLIENT_CLASS))
        .or(ElementMatchers.hasSuperType(ElementMatchers.named(HTTP_ASYNC_REQUEST_PRODUCER_CLASS)));
  }

  public static boolean matches(Class<?> clazz) {
    if (clazz == null) {
      return false;
    }
    String className = clazz.getName();
    if (INTERNAL_HTTP_ASYNC_CLIENT_CLASS.equals(className)
        || MINIMAL_HTTP_ASYNC_CLIENT_CLASS.equals(className)
        || CLOSEABLE_HTTP_ASYNC_CLIENT_CLASS.equals(className)) {
      return true;
    }
    for (Class<?> iface : clazz.getInterfaces()) {
      if (implementsHttpAsyncRequestProducer(iface)) {
        return true;
      }
    }
    return matches(clazz.getSuperclass());
  }

  public static void trackProducer(Object producer, long requestThreadId) {
    SSLStorage.trackApacheHttpAsyncProducer(producer, requestThreadId);
  }

  public static Long producerThreadId(Object producer) {
    return SSLStorage.apacheHttpAsyncProducerThreadId(producer);
  }

  public static void removeProducer(Object producer) {
    SSLStorage.removeApacheHttpAsyncProducer(producer);
  }

  private static boolean implementsHttpAsyncRequestProducer(Class<?> type) {
    if (HTTP_ASYNC_REQUEST_PRODUCER_CLASS.equals(type.getName())) {
      return true;
    }
    for (Class<?> iface : type.getInterfaces()) {
      if (implementsHttpAsyncRequestProducer(iface)) {
        return true;
      }
    }
    return false;
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) -> {
      if (INTERNAL_HTTP_ASYNC_CLIENT_CLASS.equals(type.getName())
          || MINIMAL_HTTP_ASYNC_CLIENT_CLASS.equals(type.getName())) {
        return builder.visit(
            Advice.to(ExecuteAdvice.class)
                .on(
                    ElementMatchers.named("execute")
                        .and(
                            ElementMatchers.takesArgument(
                                0, ElementMatchers.named(HTTP_ASYNC_REQUEST_PRODUCER_CLASS)))));
      }
      if (CLOSEABLE_HTTP_ASYNC_CLIENT_CLASS.equals(type.getName())) {
        return builder.visit(
            Advice.to(ExecuteAdvice.class)
                .on(
                    ElementMatchers.named("execute")
                        .and(ElementMatchers.takesArguments(3))
                        .and(
                            ElementMatchers.takesArgument(
                                0, ElementMatchers.named(HTTP_ASYNC_REQUEST_PRODUCER_CLASS)))));
      }
      return builder
          .visit(Advice.to(ProducerCreatedAdvice.class).on(ElementMatchers.isConstructor()))
          .visit(
              Advice.to(GenerateRequestAdvice.class)
                  .on(
                      ElementMatchers.named("generateRequest")
                          .and(ElementMatchers.takesArguments(0))))
          .visit(
              Advice.to(ProduceContentAdvice.class)
                  .on(
                      ElementMatchers.named("produceContent")
                          .and(ElementMatchers.takesArguments(2))))
          .visit(
              Advice.to(CompleteRequestAdvice.class)
                  .on(ElementMatchers.namedOneOf("requestCompleted", "failed")));
    };
  }

  @SuppressWarnings("unused")
  public static final class ProducerCreatedAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit(@Advice.This Object producer) {
      long requestThreadId = Agent.NativeLib.gettid();
      trackProducer(producer, requestThreadId);
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[ApacheHttpAsyncClientInst] created producer="
                + System.identityHashCode(producer)
                + " requestThread="
                + requestThreadId);
      }
    }
  }

  @SuppressWarnings("unused")
  public static final class ExecuteAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.Argument(0) Object producer) {
      long requestThreadId = Agent.NativeLib.gettid();
      trackProducer(producer, requestThreadId);
      if (SSLStorage.bootDebugOn().equals(true)) {
        System.err.println(
            "[ApacheHttpAsyncClientInst] execute producer="
                + System.identityHashCode(producer)
                + " requestThread="
                + requestThreadId);
      }
    }
  }

  @SuppressWarnings("unused")
  public static final class GenerateRequestAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.This Object producer) {
      handoffProducerContext(producer, "generateRequest");
    }
  }

  @SuppressWarnings("unused")
  public static final class ProduceContentAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.This Object producer) {
      handoffProducerContext(producer, "produceContent");
    }
  }

  public static void handoffProducerContext(Object producer, String hook) {
    Long requestThreadId = producerThreadId(producer);
    long threadId = Agent.NativeLib.gettid();
    if (SSLStorage.bootDebugOn().equals(true)) {
      System.err.println(
          "[ApacheHttpAsyncClientInst] "
              + hook
              + " producer="
              + System.identityHashCode(producer)
              + " requestThread="
              + requestThreadId
              + " currentThread="
              + Thread.currentThread().getName()
              + " ioThread="
              + threadId);
    }
    if (requestThreadId != null && requestThreadId.longValue() != threadId) {
      ThreadInfo.sendTaskParentThreadContext(requestThreadId);
    }
  }

  @SuppressWarnings("unused")
  public static final class CompleteRequestAdvice {
    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.This Object producer) {
      removeProducer(producer);
    }
  }
}
