package com.github.j3t.ssl.utils;

import com.github.j3t.ssl.utils.types.SslProtocol;
import org.junit.Test;
import org.mockito.internal.verification.Times;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class SSLContextBuilderTest {
    @Test
    public void givenSSLContext_whenBuildWithSpecificProtocol_thenGetProtocolShouldReturnSpecificProtocol() throws Exception {
        SSLContext sslContext = SSLContextBuilder.create()
                .setProtocol(SslProtocol.SSLv3)
                .build();

        assertEquals(SslProtocol.SSLv3, sslContext.getProtocol());
    }

    @Test
    public void givenSSLContext_whenBuildWithSecureRandomGenerator_thenSecureRandomGeneratorShouldBeAccessedDuringHandshake() throws Exception {
        SecureRandom randomGenerator = mock(SecureRandom.class);

        SSLContext sslContext = SSLContextBuilder.create()
                .setSecureRandomGenerator(randomGenerator)
                .build();

        SSLEngine sslEngine = sslContext.createSSLEngine();
        sslEngine.setUseClientMode(true);
        verify(randomGenerator, new Times(0)).nextBytes(any(byte[].class));

        sslEngine.beginHandshake();
        verify(randomGenerator).nextBytes(any(byte[].class));
    }
}
