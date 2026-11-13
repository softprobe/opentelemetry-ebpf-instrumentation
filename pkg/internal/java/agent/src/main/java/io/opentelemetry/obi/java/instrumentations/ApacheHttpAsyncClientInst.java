/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.ebpf.ThreadInfo;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class ApacheHttpAsyncClientInst {
  private static final String EXCHANGE_HANDLER_INTERFACE =
      "org.apache.http.nio.protocol.HttpAsyncClientExchangeHandler";
  private static final String CONN_MANAGER_INTERFACE =
      "org.apache.http.nio.conn.NHttpClientConnectionManager";
  private static final String FUTURE_CALLBACK_INTERFACE =
      "org.apache.http.concurrent.FutureCallback";
  private static final String SSL_IO_SESSION_CLASS = "org.apache.http.nio.reactor.ssl.SSLIOSession";

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.not(ElementMatchers.isInterface())
        .and(
            ElementMatchers.named(SSL_IO_SESSION_CLASS)
                .or(ElementMatchers.hasSuperType(ElementMatchers.named(EXCHANGE_HANDLER_INTERFACE)))
                .or(ElementMatchers.hasSuperType(ElementMatchers.named(CONN_MANAGER_INTERFACE)))
                .or(
                    ElementMatchers.hasSuperType(
                        ElementMatchers.named(FUTURE_CALLBACK_INTERFACE))));
  }

  public static boolean matches(Class<?> clazz) {
    if (clazz.isInterface()) {
      return false;
    }
    if (SSL_IO_SESSION_CLASS.equals(clazz.getName())) {
      return true;
    }
    return implementsNamedInterface(clazz, EXCHANGE_HANDLER_INTERFACE)
        || implementsNamedInterface(clazz, CONN_MANAGER_INTERFACE)
        || implementsNamedInterface(clazz, FUTURE_CALLBACK_INTERFACE);
  }

  private static boolean implementsNamedInterface(Class<?> clazz, String target) {
    for (Class<?> cur = clazz; cur != null; cur = cur.getSuperclass()) {
      for (Class<?> iface : cur.getInterfaces()) {
        if (matchesInterfaceHierarchy(iface, target)) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean matchesInterfaceHierarchy(Class<?> iface, String target) {
    if (target.equals(iface.getName())) {
      return true;
    }
    for (Class<?> parent : iface.getInterfaces()) {
      if (matchesInterfaceHierarchy(parent, target)) {
        return true;
      }
    }
    return false;
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) -> {
      if (type.getName().equals(SSL_IO_SESSION_CLASS)) {
        return builder.visit(
            Advice.to(SSLIOSessionAdvice.class)
                .on(
                    ElementMatchers.namedOneOf("doWrap", "doUnwrap", "writePlain", "decryptData")
                        .and(ElementMatchers.not(ElementMatchers.isAbstract()))));
      }
      if (ElementMatchers.hasSuperType(ElementMatchers.named(EXCHANGE_HANDLER_INTERFACE))
          .matches(type)) {
        builder =
            builder
                .visit(Advice.to(TrackSelfAdvice.class).on(ElementMatchers.isConstructor()))
                .visit(
                    Advice.to(ExchangeStepAdvice.class)
                        .on(
                            ElementMatchers.namedOneOf(
                                    "start",
                                    "produceRequest",
                                    "produceContent",
                                    "requestCompleted",
                                    "responseReceived",
                                    "consumeContent")
                                .and(ElementMatchers.not(ElementMatchers.isAbstract()))))
                .visit(
                    Advice.to(ExchangeTerminalAdvice.class)
                        .on(
                            ElementMatchers.namedOneOf("responseCompleted", "failed", "cancel")
                                .and(ElementMatchers.not(ElementMatchers.isAbstract()))));
      }
      return builder
          .visit(
              Advice.to(LeaseConnectionAdvice.class)
                  .on(
                      ElementMatchers.named("leaseConnection")
                          .and(ElementMatchers.takesArguments(6))
                          .and(ElementMatchers.not(ElementMatchers.isAbstract()))))
          .visit(
              Advice.to(FutureCallbackCompletedAdvice.class)
                  .on(
                      ElementMatchers.named("completed")
                          .and(ElementMatchers.takesArguments(1))
                          .and(ElementMatchers.not(ElementMatchers.isAbstract()))));
    };
  }

  @SuppressWarnings("unused")
  public static final class TrackSelfAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit(@Advice.This Object self) {
      if (ThreadInfo.loomTaskOrVirtualThread(self)) {
        return;
      }
      SSLStorage.trackTask(ThreadInfo.currentTid(), self);
    }
  }

  @SuppressWarnings("unused")
  public static final class ExchangeStepAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.This Object self) {
      SSLStorage.propagateParentIfTracked(self);
    }
  }

  @SuppressWarnings("unused")
  public static final class ExchangeTerminalAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.This Object self) {
      SSLStorage.propagateParentIfTracked(self);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.This Object self) {
      SSLStorage.untrackTask(self);
    }
  }

  @SuppressWarnings("unused")
  public static final class LeaseConnectionAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.Argument(5) Object callback) {
      if (callback == null || ThreadInfo.loomTaskOrVirtualThread(callback)) {
        return;
      }
      SSLStorage.trackTask(ThreadInfo.currentTid(), callback);
    }
  }

  @SuppressWarnings("unused")
  public static final class FutureCallbackCompletedAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.This Object self) {
      SSLStorage.propagateParentIfTracked(self);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.This Object self) {
      SSLStorage.untrackTask(self);
    }
  }

  @SuppressWarnings("unused")
  public static final class SSLIOSessionAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object enter(@Advice.This Object session) {
      if (session == null) {
        return null;
      }
      try {
        @SuppressWarnings("unchecked")
        ThreadLocal<Object> threadLocal =
            (ThreadLocal<Object>) SSLStorage.getBootNettyConnectionField().get(null);
        Object previous = threadLocal.get();
        Object c = SSLStorage.getBootExtractIOSessionMethod().invoke(null, session);
        if (c != null) {
          threadLocal.set(c);
        }
        return previous;
      } catch (Exception ignored) {
        return null;
      }
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter Object previous) {
      try {
        @SuppressWarnings("unchecked")
        ThreadLocal<Object> threadLocal =
            (ThreadLocal<Object>) SSLStorage.getBootNettyConnectionField().get(null);
        if (previous != null) {
          threadLocal.set(previous);
        } else {
          threadLocal.remove();
        }
      } catch (Exception ignored) {
      }
    }
  }
}
