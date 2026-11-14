import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

public class MockServerAndSink {
    private static final byte[] ERROR_BODY =
        ("{\"error\":\"bad offer\",\"code\":\"OFFER_EXPIRED\",\"detail\":\"" + "x".repeat(160) + "\"}")
            .getBytes(StandardCharsets.UTF_8);

    private static void handleMock(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            in.readAllBytes();
        }
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.getResponseHeaders().set("Connection", "keep-alive");
        ex.sendResponseHeaders(400, ERROR_BODY.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(ERROR_BODY);
        }
    }

    public static void main(String[] args) throws Exception {
        Path workDir = Path.of(args[0]);
        Path keystorePath = Path.of(args[1]);
        char[] pass = "changeit".toCharArray();

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keystorePath.toFile())) {
            ks.load(fis, pass);
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, pass);
        SSLContext serverCtx = SSLContext.getInstance("TLS");
        serverCtx.init(kmf.getKeyManagers(), null, new SecureRandom());

        HttpServer httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        httpServer.createContext("/ndc/v21.3/offerprice", MockServerAndSink::handleMock);
        httpServer.setExecutor(Executors.newCachedThreadPool());
        httpServer.start();

        HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(serverCtx));
        httpsServer.createContext("/ndc/v21.3/offerprice", MockServerAndSink::handleMock);
        httpsServer.setExecutor(Executors.newCachedThreadPool());
        httpsServer.start();

        AtomicInteger otlpBytes = new AtomicInteger();
        HttpServer otlpSink = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        otlpSink.createContext("/v1/traces", ex -> {
            byte[] payload;
            try (InputStream in = ex.getRequestBody()) {
                payload = in.readAllBytes();
            }
            int total = otlpBytes.addAndGet(payload.length);
            Files.writeString(workDir.resolve("otlp.bytes"), Integer.toString(total));
            ex.sendResponseHeaders(200, 2);
            try (OutputStream out = ex.getResponseBody()) {
                out.write("{}".getBytes(StandardCharsets.UTF_8));
            }
        });
        otlpSink.setExecutor(Executors.newCachedThreadPool());
        otlpSink.start();

        String props = String.format(
            "HTTP_PORT=%d%nHTTPS_PORT=%d%nOTLP_PORT=%d%n",
            httpServer.getAddress().getPort(),
            httpsServer.getAddress().getPort(),
            otlpSink.getAddress().getPort()
        );
        Files.writeString(workDir.resolve("server_ports.env"), props);

        Thread.sleep(120_000L);
    }
}
