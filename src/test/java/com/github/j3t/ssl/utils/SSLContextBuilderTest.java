package com.github.j3t.ssl.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;
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
    public void givenSSLContextWithDefaultProtocol_whenJava6_thenGetProtocolShouldReturnTLSv10() throws Exception
    {
        assumeTrue("Java Version isn't 1.6!", EnvironmentHelper.isJava6());
        
        SSLContext sslContext = SSLContextBuilder.create()
                .build();
        
        assertEquals(SslProtocol.TLSv10, sslContext.getProtocol());
    }
    
    @Test
    public void givenSSLContextWithDefaultProtocol_whenJava7_thenGetProtocolShouldReturnTLSv10() throws Exception
    {
        assumeTrue("Java Version isn't 1.7!", EnvironmentHelper.isJava7());
        
        SSLContext sslContext = SSLContextBuilder.create()
                .build();
        
        assertEquals(SslProtocol.TLSv11, sslContext.getProtocol());
    }
    
    @Test
    public void givenSSLContextWithDefaultProtocol_whenJava8_thenGetProtocolShouldReturnTLSv10() throws Exception
    {
        assumeTrue("Java Version isn't 1.8!", EnvironmentHelper.isJava8());
        
        SSLContext sslContext = SSLContextBuilder.create()
                .build();
        
        assertEquals(SslProtocol.TLSv12, sslContext.getProtocol());
    }

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
