/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import static net.bytebuddy.dynamic.loading.ClassInjector.UsingInstrumentation.Target.BOOTSTRAP;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.opentelemetry.obi.java.instrumentations.data.SoftprobeTrustBridge;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.loading.ClassInjector;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.utility.JavaModule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TrustManagerInstTest {

  @TempDir Path tempDir;

  @AfterEach
  void cleanup() throws Exception {
    SoftprobeTrustBridge.clearForTest();
    try {
      Class<?> bootBridge =
          Class.forName(
              "io.opentelemetry.obi.java.instrumentations.data.SoftprobeTrustBridge", true, null);
      bootBridge.getMethod("clearForTest").invoke(null);
    } catch (ClassNotFoundException ignored) {
    }
  }

  @Test
  void retransformsPreExistingTrustManagerAndPreservesDefaultValidation() throws Exception {
    File caKeystore = tempDir.resolve("ca.p12").toFile();
    File caPem = tempDir.resolve("sp-obi-ca.pem").toFile();
    File leafKeystore = tempDir.resolve("leaf.p12").toFile();
    File leafCsr = tempDir.resolve("leaf.csr").toFile();
    File leafPem = tempDir.resolve("leaf.pem").toFile();
    File rogueKeystore = tempDir.resolve("rogue.p12").toFile();
    File roguePem = tempDir.resolve("rogue.pem").toFile();

    runKeytool(
        "-genkeypair",
        "-alias",
        "ca",
        "-keyalg",
        "EC",
        "-keysize",
        "256",
        "-dname",
        "CN=Softprobe OBI Ephemeral Root CA,O=Softprobe",
        "-ext",
        "bc:c",
        "-keystore",
        caKeystore.getAbsolutePath(),
        "-storetype",
        "PKCS12",
        "-storepass",
        "changeit",
        "-keypass",
        "changeit");
    runKeytool(
        "-exportcert",
        "-rfc",
        "-alias",
        "ca",
        "-keystore",
        caKeystore.getAbsolutePath(),
        "-storepass",
        "changeit",
        "-file",
        caPem.getAbsolutePath());

    runKeytool(
        "-genkeypair",
        "-alias",
        "leaf",
        "-keyalg",
        "EC",
        "-keysize",
        "256",
        "-dname",
        "CN=spair.softprobe.ai",
        "-keystore",
        leafKeystore.getAbsolutePath(),
        "-storetype",
        "PKCS12",
        "-storepass",
        "changeit",
        "-keypass",
        "changeit");
    runKeytool(
        "-certreq",
        "-alias",
        "leaf",
        "-keystore",
        leafKeystore.getAbsolutePath(),
        "-storepass",
        "changeit",
        "-file",
        leafCsr.getAbsolutePath());
    runKeytool(
        "-gencert",
        "-rfc",
        "-alias",
        "ca",
        "-keystore",
        caKeystore.getAbsolutePath(),
        "-storepass",
        "changeit",
        "-infile",
        leafCsr.getAbsolutePath(),
        "-outfile",
        leafPem.getAbsolutePath(),
        "-ext",
        "san=dns:spair.softprobe.ai",
        "-ext",
        "eku=serverAuth");

    runKeytool(
        "-genkeypair",
        "-alias",
        "rogue",
        "-keyalg",
        "EC",
        "-keysize",
        "256",
        "-dname",
        "CN=spair.softprobe.ai",
        "-keystore",
        rogueKeystore.getAbsolutePath(),
        "-storetype",
        "PKCS12",
        "-storepass",
        "changeit",
        "-keypass",
        "changeit");
    runKeytool(
        "-exportcert",
        "-rfc",
        "-alias",
        "rogue",
        "-keystore",
        rogueKeystore.getAbsolutePath(),
        "-storepass",
        "changeit",
        "-file",
        roguePem.getAbsolutePath());

    X509Certificate caCert = readCert(caPem);
    X509Certificate leafCert = readCert(leafPem);
    X509Certificate rogueCert = readCert(roguePem);

    TrustManagerFactory tmf =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init((KeyStore) null);
    X509TrustManager preExistingTm = null;
    for (TrustManager candidate : tmf.getTrustManagers()) {
      if (candidate instanceof X509TrustManager) {
        preExistingTm = (X509TrustManager) candidate;
        break;
      }
    }
    assertTrue(preExistingTm instanceof X509ExtendedTrustManager);
    X509ExtendedTrustManager extTm = (X509ExtendedTrustManager) preExistingTm;

    Instrumentation inst = ByteBuddyAgent.install();
    File injectDir = tempDir.resolve("boot-inject").toFile();
    assertTrue(injectDir.mkdirs());
    TypeDescription bridgeDesc = TypeDescription.ForLoadedType.of(SoftprobeTrustBridge.class);
    byte[] bridgeBytes =
        ClassFileLocator.ForClassLoader.of(SoftprobeTrustBridge.class.getClassLoader())
            .locate(SoftprobeTrustBridge.class.getName())
            .resolve();
    ClassInjector.UsingInstrumentation.of(injectDir, BOOTSTRAP, inst)
        .inject(Collections.singletonMap(bridgeDesc, bridgeBytes));

    new AgentBuilder.Default()
        .with(
            new AgentBuilder.LocationStrategy() {
              @Override
              public ClassFileLocator classFileLocator(ClassLoader classLoader, JavaModule module) {
                return ClassFileLocator.ForClassLoader.of(classLoader);
              }
            })
        .disableClassFormatChanges()
        .ignore(ElementMatchers.nameStartsWith("io.opentelemetry.obi"))
        .with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
        .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
        .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
        .type(TrustManagerInst.type())
        .transform(TrustManagerInst.transformer())
        .installOn(inst);

    assertTrue(TrustManagerInst.matches(extTm.getClass()));
    inst.retransformClasses(extTm.getClass());

    assertThrows(
        CertificateException.class,
        () -> extTm.checkServerTrusted(new X509Certificate[] {leafCert, caCert}, "ECDHE_ECDSA"));

    SoftprobeTrustBridge.installCaFile(caPem.getAbsolutePath());
    Class<?> bootBridge =
        Class.forName(
            "io.opentelemetry.obi.java.instrumentations.data.SoftprobeTrustBridge", true, null);
    bootBridge.getMethod("installCaFile", String.class).invoke(null, caPem.getAbsolutePath());

    X509Certificate[] chain = new X509Certificate[] {leafCert, caCert};
    assertDoesNotThrow(() -> extTm.checkServerTrusted(chain, "ECDHE_ECDSA"));
    assertDoesNotThrow(() -> extTm.checkServerTrusted(chain, "ECDHE_ECDSA", (Socket) null));
    assertDoesNotThrow(() -> extTm.checkServerTrusted(chain, "ECDHE_ECDSA", (SSLEngine) null));
    assertTrue(Arrays.asList(extTm.getAcceptedIssuers()).contains(caCert));

    assertThrows(
        CertificateException.class,
        () -> extTm.checkServerTrusted(new X509Certificate[] {rogueCert}, "ECDHE_ECDSA"));
    assertThrows(
        CertificateException.class,
        () ->
            extTm.checkServerTrusted(
                new X509Certificate[] {rogueCert}, "ECDHE_ECDSA", (SSLEngine) null));
  }

  private static void runKeytool(String... args) throws Exception {
    File javaHome = new File(System.getProperty("java.home"));
    File keytool = new File(new File(javaHome, "bin"), "keytool");
    String[] cmd = new String[args.length + 1];
    cmd[0] = keytool.getAbsolutePath();
    System.arraycopy(args, 0, cmd, 1, args.length);
    Process proc = new ProcessBuilder(cmd).redirectErrorStream(true).start();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try (InputStream in = proc.getInputStream()) {
      byte[] buf = new byte[1024];
      int read;
      while ((read = in.read(buf)) != -1) {
        out.write(buf, 0, read);
      }
    }
    int code = proc.waitFor();
    if (code != 0) {
      throw new IllegalStateException(
          "keytool exited with code "
              + code
              + ": "
              + new String(out.toByteArray(), StandardCharsets.UTF_8));
    }
  }

  private static X509Certificate readCert(File pemFile) throws Exception {
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    try (InputStream in = new FileInputStream(pemFile)) {
      return (X509Certificate) factory.generateCertificate(in);
    }
  }
}
