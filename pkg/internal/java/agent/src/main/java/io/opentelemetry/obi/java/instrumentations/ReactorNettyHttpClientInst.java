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

public class ReactorNettyHttpClientInst {
  private static final String OBSERVER_CLASS =
      "reactor.netty.http.client.HttpClientConnect$HttpIOHandlerObserver";
  private static final String HTTP_OBSERVER_CLASS =
      "reactor.netty.http.client.HttpClientConnect$HttpObserver";

  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.namedOneOf(OBSERVER_CLASS, HTTP_OBSERVER_CLASS);
  }

  public static boolean matches(Class<?> clazz) {
    String name = clazz.getName();
    return OBSERVER_CLASS.equals(name) || HTTP_OBSERVER_CLASS.equals(name);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(Advice.to(ConstructorAdvice.class).on(ElementMatchers.isConstructor()))
            .visit(
                Advice.to(StateChangeAdvice.class)
                    .on(
                        ElementMatchers.named("onStateChange")
                            .and(ElementMatchers.takesArguments(2))
                            .and(ElementMatchers.not(ElementMatchers.isAbstract()))));
  }

  @SuppressWarnings("unused")
  public static final class ConstructorAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit(@Advice.This Object self) {
      if (ThreadInfo.loomTaskOrVirtualThread(self)) {
        return;
      }
      SSLStorage.trackTask(ThreadInfo.currentTid(), self);
    }
  }

  @SuppressWarnings("unused")
  public static final class StateChangeAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.This Object self) {
      SSLStorage.propagateParentIfTracked(self);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.This Object self, @Advice.Argument(1) Object newState) {
      if (newState != null && "DISCONNECTING".equals(newState.toString())) {
        SSLStorage.untrackTask(self);
      }
    }
  }
}
