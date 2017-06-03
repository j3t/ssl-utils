package com.github.j3t.ssl.utils;

import com.github.j3t.ssl.utils.strategy.TrustManagerStrategy;
import com.github.j3t.ssl.utils.types.SslProtocol;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests specific {@link SSLContextBuilder} configurations. Some of these tests are exists to increase the code
 * coverage.
 */
public class SSLContextBuilderTest {

    @Test
    public void testSSLContextWithSpecificProtocol() throws Exception {
        // given SSLContextBuilder is set up with a specific SSL protocol
        SSLContext sslContext = SSLContextBuilder.create()
                .setProtocol(SslProtocol.SSLv3)

                // when SSLContext created
                .build();

        // then the SSLContext should return the specific protocol
        assertEquals(SslProtocol.SSLv3, sslContext.getProtocol());
    }

    @Test
    public void testSSLContextWithCustomRandomGenerator() throws Exception {
        // given SSLContext with a custom random generator
        SecureRandom randomGenerator = mock(SecureRandom.class);
        SSLContext sslContext = SSLContextBuilder.create()
                .setSecureRandomGenerator(randomGenerator)
                .build();

        // when SSLEngine is created from the context and the handshake has started
        SSLEngine sslEngine = sslContext.createSSLEngine();
        sslEngine.setUseClientMode(true);
        sslEngine.beginHandshake();

        // then the custom random generator should be used
        verify(randomGenerator).nextBytes(any(byte[].class));
    }

    @Test(expected = NoSuchAlgorithmException.class)
    public void testSSLContextWithInvalidTrustManagerAlgorithm() throws Exception {
        // given SSLContextBuilder with an invalid trust manager algorithm
        SSLContextBuilder.create()
                .setTrustManagerAlgorithm("ForceNoSuchAlgorithmException")
                // when build is started
                .build();
        // then exception should be thrown
    }

    @Test
    public void testSSLContextWithWrongKeyStorePassword() throws Exception {
        // given SSLContextBuilder without key store password
        SSLContextBuilder.create()
                .setKeyStorePassword((String) null)
                .build();
    }

    @Test(expected = NoSuchAlgorithmException.class)
    public void testSSLContextWithInvalidKeyManagerAlgorithm() throws Exception {
        // given SSLContextBuilder with an invalid key manager algorithm
        SSLContextBuilder.create()
                .setKeyManagerAlgorithm("ForceNoSuchAlgorithmException")
                .setKeyStore(KeyStore.getInstance(KeyStore.getDefaultType()))
                // when build is started
                .build();
        // then exception should be thrown
    }
}
