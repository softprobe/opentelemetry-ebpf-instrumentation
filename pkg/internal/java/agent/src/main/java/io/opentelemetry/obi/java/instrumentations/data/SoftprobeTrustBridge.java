/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public final class SoftprobeTrustBridge {
  public static volatile X509Certificate trustedCa;

  private SoftprobeTrustBridge() {}

  public static void installCaFile(String pemPath) throws Exception {
    if (pemPath == null || pemPath.isEmpty()) {
      return;
    }
    File file = new File(pemPath);
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    try (InputStream in = new FileInputStream(file)) {
      Certificate cert = factory.generateCertificate(in);
      if (cert instanceof X509Certificate) {
        trustedCa = (X509Certificate) cert;
      }
    }
  }

  public static void clearForTest() {
    trustedCa = null;
  }

  public static boolean isTrustedBySoftprobeCa(X509Certificate[] chain) {
    X509Certificate ca = trustedCa;
    if (ca == null || chain == null || chain.length == 0 || chain[0] == null) {
      return false;
    }
    try {
      boolean issuerMatched = false;
      for (int i = 0; i < chain.length; i++) {
        X509Certificate cert = chain[i];
        if (cert != null && ca.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
          issuerMatched = true;
          break;
        }
      }
      if (!issuerMatched) {
        return false;
      }

      ca.checkValidity();
      X509Certificate leaf = chain[0];
      leaf.checkValidity();
      if (ca.equals(leaf)) {
        leaf.verify(ca.getPublicKey());
        return true;
      }
      if (!ca.getSubjectX500Principal().equals(leaf.getIssuerX500Principal())) {
        return false;
      }
      leaf.verify(ca.getPublicKey());
      return true;
    } catch (Throwable ignored) {
      return false;
    }
  }

  public static X509Certificate[] appendAcceptedIssuer(X509Certificate[] existing) {
    X509Certificate ca = trustedCa;
    if (ca == null) {
      return existing;
    }
    if (existing == null || existing.length == 0) {
      return new X509Certificate[] {ca};
    }
    for (int i = 0; i < existing.length; i++) {
      if (ca.equals(existing[i])) {
        return existing;
      }
    }
    X509Certificate[] merged = new X509Certificate[existing.length + 1];
    System.arraycopy(existing, 0, merged, 0, existing.length);
    merged[existing.length] = ca;
    return merged;
  }
}
