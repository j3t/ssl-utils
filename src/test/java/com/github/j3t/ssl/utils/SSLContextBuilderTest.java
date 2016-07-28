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
    public void setProtocolShouldBeTheSameWhenTheSSLContextIsCreated() throws Exception
    {
        SSLContext sslContext = SSLContextBuilder.create()
                .setProtocol(SslProtocol.TLSv11)
                .build();
        
        assertEquals(SslProtocol.TLSv11, sslContext.getProtocol());
    }

    @Test
    public void setSecureRandomGeneratorShouldBeInvokedWhenSSLContextIsUsed() throws Exception
    {
        SecureRandom randomGenarator = mock(SecureRandom.class);
        
        SSLContext sslContext = SSLContextBuilder.create()
                .setSecureRandomGenerator(randomGenarator)
                .build();

        verify(randomGenarator, new Times(0)).nextBytes(any(byte[].class));
        
        SSLEngine sslEngine = sslContext.createSSLEngine();
        sslEngine.setUseClientMode(true);
        sslEngine.beginHandshake();
        
        verify(randomGenarator).nextBytes(any(byte[].class));
    }
}
