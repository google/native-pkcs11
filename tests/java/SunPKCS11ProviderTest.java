
// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import static java.nio.charset.StandardCharsets.UTF_8;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

// https://docs.oracle.com/en/java/javase/21/security/pkcs11-reference-guide1.html

public final class SunPKCS11ProviderTest {
  private static final String HTTP_BODY = "hello world\n";
  private static final String SSL_CONTEXT_PROTOCOL = "TLS";

  private static PrivateKey loadPrivateKey(Path path) throws Exception {
    KeySpec keySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(path));
    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    return keyFactory.generatePrivate(keySpec);
  }

  private static Certificate loadCertificate(Path path) throws Exception {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    return certificateFactory.generateCertificate(Files.newInputStream(path));
  }

  private static SSLContext serverSslContext(Path serverKey, Path serverCert, Path clientRoot)
      throws Exception {
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    keyStore.setKeyEntry(
        "server", loadPrivateKey(serverKey), null, new Certificate[] {loadCertificate(serverCert)});

    KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, null);

    KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    trustStore.setCertificateEntry("clientRoot", loadCertificate(clientRoot));

    TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);

    SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT_PROTOCOL);
    sslContext.init(
        keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
    return sslContext;
  }

  private static SSLContext clientSslContext(Path pkcs11Config, Path serverRoot) throws Exception {
    Provider provider = Security.getProvider("SunPKCS11").configure(pkcs11Config.toString());
    Security.addProvider(provider);

    KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
    keyStore.load(null, null);

    KeyManagerFactory keyManagerFactory =
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, null);

    KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    trustStore.setCertificateEntry("serverRoot", loadCertificate(serverRoot));

    TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);

    SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT_PROTOCOL);
    sslContext.init(
        keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
    return sslContext;
  }

  static HttpsServer spawnServer(Path serverKey, Path serverCert, Path clientRoot)
      throws Exception {
    SSLContext sslContext = serverSslContext(serverKey, serverCert, clientRoot);

    HttpsServer server = HttpsServer.create(new InetSocketAddress(0), 0);
    server.setHttpsConfigurator(
        new HttpsConfigurator(sslContext) {
          @Override
          public void configure(HttpsParameters params) {
            SSLParameters sslParameters = getSSLContext().getDefaultSSLParameters();
            sslParameters.setNeedClientAuth(true);
            params.setSSLParameters(sslParameters);
          }
        });

    server.createContext(
        "/",
        exchange -> {
          exchange.sendResponseHeaders(200, HTTP_BODY.length());
          try (OutputStream os = exchange.getResponseBody()) {
            os.write(HTTP_BODY.getBytes(UTF_8));
          }
        });

    server.start();
    return server;
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 5) {
      System.out.println(
          "SunPKCS11ProviderTest <pkcs11Config> <serverKey> <serverCert> <serverRoot> <clientRoot>");
      System.exit(1);
    }
    Path pkcs11Config = Paths.get(args[0]);
    Path serverKey = Paths.get(args[1]);
    Path serverCert = Paths.get(args[2]);
    Path serverRoot = Paths.get(args[3]);
    Path clientRoot = Paths.get(args[4]);
    HttpsServer server = spawnServer(serverKey, serverCert, clientRoot);
    URI serveUri =
        new URI("https", null, "localhost", server.getAddress().getPort(), "/", null, null);

    try {
      HttpClient client = HttpClient.newBuilder().sslContext(clientSslContext(pkcs11Config, serverRoot)).build();
      HttpRequest request = HttpRequest.newBuilder().uri(serveUri).build();
      HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
      if (response.statusCode() != 200 || !response.body().equals(HTTP_BODY)) {
        throw new AssertionError("unexpected response");
      }
    } catch (SocketException e) {
      throw e;
    } finally {
      server.stop(0);
    }
  }

  private SunPKCS11ProviderTest() {}
}
