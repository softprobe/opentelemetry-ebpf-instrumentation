/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class SSLAlpnPreferenceInst {
  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.not(ElementMatchers.isInterface())
        .and(
            ElementMatchers.isSubTypeOf(SSLSocket.class)
                .or(ElementMatchers.isSubTypeOf(SSLEngine.class)));
  }

  public static boolean matches(Class<?> clazz) {
    return !clazz.isInterface()
        && (SSLSocket.class.isAssignableFrom(clazz) || SSLEngine.class.isAssignableFrom(clazz));
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder.visit(
            Advice.to(SetSSLParametersAdvice.class)
                .on(
                    ElementMatchers.named("setSSLParameters")
                        .and(ElementMatchers.takesArguments(SSLParameters.class))
                        .and(ElementMatchers.not(ElementMatchers.isAbstract()))));
  }

  @SuppressWarnings("unused")
  public static final class SetSSLParametersAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.Argument(0) SSLParameters params) {
      SSLStorage.applyHttp1AlpnPreference(params);
    }
  }
}
