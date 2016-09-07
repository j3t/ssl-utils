package com.github.j3t.ssl.utils;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.security.SecureRandom;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.junit.Test;
import org.mockito.internal.verification.Times;

import com.github.j3t.ssl.utils.types.SslProtocol;

public class SSLContextBuilderTest
{
    @Test
    public void givenSSLContext_whenBuildWithSpecificProtocol_thenGetProtocolShouldReturnSpecificProtocol() throws Exception
    {
        SSLContext sslContext = SSLContextBuilder.create()
                .setProtocol(SslProtocol.SSLv3)
                .build();
        
        assertEquals(SslProtocol.SSLv3, sslContext.getProtocol());
    }

    @Test
    public void givenSSLContext_whenBuildWithSecureRandomGenerator_thenSecureRandomGeneratorShouldBeAccessedDuringHandshake() throws Exception
    {
        SecureRandom randomGenarator = mock(SecureRandom.class);
        
        SSLContext sslContext = SSLContextBuilder.create()
                .setSecureRandomGenerator(randomGenarator)
                .build();

        SSLEngine sslEngine = sslContext.createSSLEngine();
        sslEngine.setUseClientMode(true);
        verify(randomGenarator, new Times(0)).nextBytes(any(byte[].class));

        sslEngine.beginHandshake();
        verify(randomGenarator).nextBytes(any(byte[].class));
    }
}
