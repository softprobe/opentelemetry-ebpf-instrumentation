import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class VerifyJavaHttp {
    private static String readFirst16Bytes(InputStream in) throws IOException {
        byte[] buf = new byte[16];
        int n = 0;
        for (; n < buf.length; n++) {
            int b = in.read();
            if (b == -1) break;
            buf[n] = (byte) b;
        }
        return new String(buf, 0, n, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        Path workDir = Path.of(args[0]);
        int httpPort = Integer.parseInt(args[1]);
        int httpsPort = Integer.parseInt(args[2]);

        TrustManager[] trustAll = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
            }
        };
        SSLContext clientCtx = SSLContext.getInstance("TLS");
        clientCtx.init(null, trustAll, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(clientCtx.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);

        try (ServerSocket marker = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            Files.writeString(workDir.resolve("client_port.env"), "LISTEN_PORT=" + marker.getLocalPort() + "\n");

            Path readyFlag = workDir.resolve("ready.flag");
            long deadline = System.currentTimeMillis() + 45_000L;
            while (!Files.exists(readyFlag)) {
                if (System.currentTimeMillis() > deadline) {
                    throw new IllegalStateException("Timed out waiting for OBI readiness signal");
                }
                Thread.sleep(200);
            }

            HttpsURLConnection httpsConn = (HttpsURLConnection) new URL(
                "https://127.0.0.1:" + httpsPort + "/ndc/v21.3/offerprice"
            ).openConnection();
            httpsConn.setRequestMethod("POST");
            httpsConn.setDoOutput(true);
            httpsConn.setRequestProperty("Content-Type", "application/json");
            OutputStream out1 = httpsConn.getOutputStream();
            out1.write("{\"offerId\":\"OFFER-1\"}".getBytes(StandardCharsets.UTF_8));
            out1.flush();
            int code1 = httpsConn.getResponseCode();
            String part1 = readFirst16Bytes(httpsConn.getErrorStream());
            System.out.println("[JAVA] HTTPS status=" + code1 + " partial=" + part1);

            HttpURLConnection httpConn = (HttpURLConnection) new URL(
                "http://127.0.0.1:" + httpPort + "/ndc/v21.3/offerprice"
            ).openConnection();
            httpConn.setRequestMethod("POST");
            httpConn.setDoOutput(true);
            httpConn.setRequestProperty("Content-Type", "application/json");
            OutputStream out2 = httpConn.getOutputStream();
            out2.write("{\"offerId\":\"OFFER-2\"}".getBytes(StandardCharsets.UTF_8));
            out2.flush();
            int code2 = httpConn.getResponseCode();
            String part2 = readFirst16Bytes(httpConn.getErrorStream());
            System.out.println("[JAVA] HTTP status=" + code2 + " partial=" + part2);
            System.out.flush();

            // Keep both connections open without closing streams until spans are observed.
            Path doneFlag = workDir.resolve("done.flag");
            long flushDeadline = System.currentTimeMillis() + 30_000L;
            while (!Files.exists(doneFlag)) {
                if (System.currentTimeMillis() > flushDeadline) {
                    break;
                }
                Thread.sleep(200);
            }
        }
    }
}
