/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import io.opentelemetry.obi.java.instrumentations.data.SoftprobeTrustBridge;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

public class TrustManagerInst {
  public static ElementMatcher<? super TypeDescription> type() {
    return ElementMatchers.not(ElementMatchers.isInterface())
        .and(ElementMatchers.isSubTypeOf(X509TrustManager.class));
  }

  public static boolean matches(Class<?> clazz) {
    return !clazz.isInterface() && X509TrustManager.class.isAssignableFrom(clazz);
  }

  public static AgentBuilder.Transformer transformer() {
    return (builder, type, classLoader, module, protectionDomain) ->
        builder
            .visit(
                Advice.to(CheckServerTrustedAdvice.class)
                    .on(
                        ElementMatchers.named("checkServerTrusted")
                            .and(ElementMatchers.takesArgument(0, X509Certificate[].class))
                            .and(ElementMatchers.not(ElementMatchers.isAbstract()))))
            .visit(
                Advice.to(GetAcceptedIssuersAdvice.class)
                    .on(
                        ElementMatchers.named("getAcceptedIssuers")
                            .and(ElementMatchers.takesArguments(0))
                            .and(ElementMatchers.returns(X509Certificate[].class))
                            .and(ElementMatchers.not(ElementMatchers.isAbstract()))));
  }

  @SuppressWarnings("unused")
  public static final class CheckServerTrustedAdvice {
    @Advice.OnMethodEnter(skipOn = Advice.OnNonDefaultValue.class, suppress = Throwable.class)
    public static boolean enter(@Advice.Argument(0) X509Certificate[] chain) {
      return SoftprobeTrustBridge.isTrustedBySoftprobeCa(chain);
    }
  }

  @SuppressWarnings("unused")
  public static final class GetAcceptedIssuersAdvice {
    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void exit(@Advice.Return(readOnly = false) X509Certificate[] issuers) {
      issuers = SoftprobeTrustBridge.appendAcceptedIssuer(issuers);
    }
  }
}
