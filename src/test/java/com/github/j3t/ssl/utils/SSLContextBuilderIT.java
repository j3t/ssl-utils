package com.github.j3t.ssl.utils;


import com.github.j3t.ssl.utils.strategy.KeyManagerStrategy;
import com.github.j3t.ssl.utils.strategy.TrustManagerStrategy;
import com.github.j3t.ssl.utils.test.Fixtures;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.ssl.SslSocketConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Random;

import static com.github.j3t.ssl.utils.test.Fixtures.*;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

/**
 * Integration test with a local server and client. The server is started with his own key-
 * ({@link Fixtures#KEYSTORE_SERVER}) and trust-store ({@link Fixtures#TRUSTSTORE_SERVER}). Each test creates a
 * different client configuration, sends a request to the server and checked the result.
 *
 * @author j3t
 */
public class SSLContextBuilderIT {
    private static URI request;

    @BeforeClass
    public static void startServerOnRandomListenerPort() throws Exception {
        int port = new Random().nextInt(1024 * 64 - 1 - 1024) + 1024;
        request = new URI("https", null, "localhost", port, null, null, null);

        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setKeyStore(KEYSTORE_SERVER);
        sslContextFactory.setKeyStorePassword("EC\\sEOoY");
        sslContextFactory.setTrustStore(TRUSTSTORE_SERVER);
        sslContextFactory.setNeedClientAuth(true);

        SslSocketConnector https = new SslSocketConnector(sslContextFactory);
        https.setPort(port);

        Server server = new Server();
        server.addConnector(https);
        server.setStopAtShutdown(true);
        server.setHandler(new AbstractHandler() {

            @Override
            public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
                    throws IOException, ServletException {
                response.setStatus(HttpStatus.OK_200);
                response.getWriter().print("Ok");
                baseRequest.setHandled(true);
            }
        });
        server.start();
    }

    private String executeRequest(SSLContext sslContext) throws IOException {
        BufferedReader in = null;
        try {
            HttpsURLConnection conn = (HttpsURLConnection) request.toURL().openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());

            in = new BufferedReader(new InputStreamReader(conn.getInputStream()));

            return in.readLine();
        } finally {
            if (in != null)
                in.close();
        }
    }

    @Test(expected = SSLHandshakeException.class)
    public void givenClientWithoutKeyAndTrustMaterial_whenRequestExecuted_thenExceptionShouldBeThrown() throws Exception {
        SSLContext sslContext = SSLContextBuilder.create()
                .build();

        executeRequest(sslContext);
    }

    @Test(expected = UnrecoverableKeyException.class)
    public void givenClientWithoutKeyMaterialPassword_whenRequestExecuted_thenExceptionShouldBeThrown() throws Exception {
        SSLContext sslContext = SSLContextBuilder.create()
                .setKeyStore(KEYSTORE_CLIENT)
                .build();

        executeRequest(sslContext);
    }

    @Test(expected = SSLHandshakeException.class)
    public void givenUntrustedClientAndUntrustedServer_whenRequestExecuted_thenExceptionShouldBeThrown() throws Exception {
        SSLContext sslContext = SSLContextBuilder.create()
                .setKeyStore(KEYSTORE_UNKNOWN_CLIENT)
                .setKeyStorePassword("changeit")
                .build();

        executeRequest(sslContext);
    }

    // expected exception: windows = SocketException, osx/linux = SSLHandshakeException
    @Test(expected = IOException.class)
    public void givenClientWithoutKeyMaterialAndTrustedServer_whenRequestExecuted_thenExceptionShouldBeThrown() throws Exception {
        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(TRUSTSTORE_CLIENT)
                .build();

        executeRequest(sslContext);
    }

    // expected exception: windows = SSLHandshakeException, osx/linux = SocketException
    @Test(expected = IOException.class)
    public void giveUntrustedClientAndTrustedServer_whenRequestExecuted_thenExceptionShouldBeThrown() throws Exception {
        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(TRUSTSTORE_CLIENT)
                .setKeyStore(KEYSTORE_UNKNOWN_CLIENT)
                .setKeyStorePassword("changeit")
                .build();

        executeRequest(sslContext);
    }

    @Test
    public void givenUntrustedClientAndTrustedServer_whenRequestExecuted_thenResponseShouldBeOk() throws Exception {
        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(TRUSTSTORE_CLIENT)
                .setKeyStore(KEYSTORE_CLIENT)
                .setKeyStorePassword("PtUPmi#o")
                .build();

        assertEquals("Ok", executeRequest(sslContext));
    }

    @Test(expected = SSLHandshakeException.class)
    public void givenTrustedClientRequestUntrustedServer_whenRequestExecuted_thenExecptionShouldBeThrown() throws Exception {
        TrustManagerStrategy trustManagerStrategy = mock(TrustManagerStrategy.class);
        when(trustManagerStrategy.checkTrusted(any(X509Certificate[].class), anyString())).thenReturn(true);

        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(TRUSTSTORE_SERVER)
                .setTrustManagerStrategy(trustManagerStrategy)
                .setKeyStore(KEYSTORE_CLIENT)
                .setKeyStorePassword("PtUPmi#o")
                .build();

        executeRequest(sslContext);
    }

    @Test
    public void givenTrustedClientAndUntrustedServer_whenRequestExecutedAndTrustManagerStrategyReturnsFalse_thenRequestShouldBeAnswered() throws Exception {
        TrustManagerStrategy trustManagerStrategy = mock(TrustManagerStrategy.class);
        when(trustManagerStrategy.checkTrusted(any(X509Certificate[].class), anyString())).thenReturn(false);

        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(TRUSTSTORE_SERVER)
                .setTrustManagerStrategy(trustManagerStrategy)
                .setKeyStore(KEYSTORE_CLIENT)
                .setKeyStorePassword("PtUPmi#o")
                .build();

        assertEquals("Ok", executeRequest(sslContext));
    }

    @Test(expected = SSLHandshakeException.class)
    public void givenTrustedClientAndTrustedServer_whenRequestExecutedAndTrustManagerStrategyThrowsException_thenExceptionShouldBeThrown() throws Exception {
        TrustManagerStrategy trustManagerStrategy = mock(TrustManagerStrategy.class);
        when(trustManagerStrategy.checkTrusted(any(X509Certificate[].class), anyString())).thenThrow(new CertificateException());

        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(TRUSTSTORE_CLIENT)
                .setTrustManagerStrategy(trustManagerStrategy)
                .setKeyStore(KEYSTORE_CLIENT)
                .setKeyStorePassword("PtUPmi#o")
                .build();

        executeRequest(sslContext);
    }

    @Test
    public void givenTrustedClientAndTrustedServer_whenRequestExecutedAndKeyManagerStrategyReturnsValidAlias_thenResponseShouldBeOk() throws Exception {
        KeyManagerStrategy keyManagerStrategy = mock(KeyManagerStrategy.class);
        when(keyManagerStrategy.chooseAlias()).thenReturn("client");

        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(TRUSTSTORE_CLIENT)
                .setKeyStore(KEYSTORE_CLIENT)
                .setKeyStorePassword("PtUPmi#o")
                .setKeyManagerStrategy(keyManagerStrategy)
                .build();

        assertEquals("Ok", executeRequest(sslContext));

        verify(keyManagerStrategy).chooseAlias();
    }

    // expected exception: windows = SocketException, osx/linux = SSLHandshakeException
    @Test(expected = IOException.class)
    public void givenTrustedClientAndTrustedServer_whenRequestExecutedAndKeyManagerStrategyReturnsInvalidAlias_thenExceptionShouldBeThrown() throws Exception {
        KeyManagerStrategy keyManagerStrategy = mock(KeyManagerStrategy.class);
        when(keyManagerStrategy.chooseAlias()).thenReturn("unknown");

        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(TRUSTSTORE_CLIENT)
                .setKeyStore(KEYSTORE_CLIENT)
                .setKeyStorePassword("PtUPmi#o")
                .setKeyManagerStrategy(keyManagerStrategy)
                .build();

        executeRequest(sslContext);
    }
}
