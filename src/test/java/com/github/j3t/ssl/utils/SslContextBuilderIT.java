
package com.github.j3t.ssl.utils;


import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.Random;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.BeforeClass;
import org.junit.Test;

import com.github.j3t.ssl.utils.strategy.KeyManagerStrategy;
import com.github.j3t.ssl.utils.strategy.TrustManagerStrategy;
import com.github.j3t.ssl.utils.types.KeyStoreType;

public class SslContextBuilderIT
{
    private static URI request;

    @BeforeClass
    public static void setUpClass() throws Exception
    {
        int port = new Random().nextInt(1024 * 64 - 1 - 1024) + 1024;
        request = new URI("https", null, "localhost", port, null, null, null);
        
        startServer(port);
    }

    private static void startServer(int port) throws Exception
    {
        Server server = new Server();

        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setKeyStorePath(SslContextBuilderIT.class.getResource("/certs/server.jks").getFile());
        sslContextFactory.setKeyStorePassword("EC\\sEOoY");
        sslContextFactory.setTrustStorePath(SslContextBuilderIT.class.getResource("/certs/server-trust.jks").getFile());
        sslContextFactory.setNeedClientAuth(true);

        ServerConnector https = new ServerConnector(
                server,
                new SslConnectionFactory(sslContextFactory, "http/1.1"),
                new HttpConnectionFactory());
        https.setPort(port);
        
        server.addConnector(https);
        server.setStopAtShutdown(true);
        server.setHandler(new AbstractHandler()
            {
                
                @Override
                public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
                {
                    response.setStatus(HttpStatus.OK_200);
                    response.getWriter().print("Ok");
                    baseRequest.setHandled(true);
                }
            });
        server.start();
        
        while (server.isStarting())
            Thread.sleep(100);
    }

    private String execute(SSLContext sslContext) throws IOException
    {
        BufferedReader in = null;
        try
        {
            HttpsURLConnection conn = (HttpsURLConnection) request.toURL().openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            
            in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            
            return in.readLine(); 
        }
        finally
        {
            if (in != null)
                in.close();
        }
    }

    @Test(expected = SSLHandshakeException.class)
    public void clientExecuteRequestShouldThrowExceptionWhenClientUnknownAndServerNotTrusted() throws Exception
    {
        SSLContext sslContext = SSLContextBuilder.create()
                .build();
        
        execute(sslContext);
    }

    @Test(expected = SSLHandshakeException.class)
    public void clientExecuteRequestShouldThrowExceptionWhenClientUnknownAndServerTrusted() throws Exception
    {
        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(SslContextBuilderIT.class.getResource("/certs/client-trust.jks").getFile())
                        .build())
                .build();
        
        execute(sslContext);
    }

    // expected exception: windows = SSLHandshakeException, linux = SocketException
    @Test(expected = IOException.class)
    public void clientExecuteRequestShouldThrowExceptionWhenClientNotTrustedAndServerTrusted() throws Exception
    {
        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(SslContextBuilderIT.class.getResource("/certs/client-trust.jks").getFile())
                        .build())
                .setKeyStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(SslContextBuilderIT.class.getResource("/certs/unknown-client.jks").getFile())
                        .build())
                .setKeyStorePassword("changeit".toCharArray())
                .build();
        
        execute(sslContext);
    }
    
    @Test(expected = UnrecoverableKeyException.class)
    public void clientExecuteRequestShouldThrowExceptionWhenKeyStorePasswordIsNotProvided() throws Exception
    {
        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(SslContextBuilderIT.class.getResource("/certs/client-trust.jks").getFile())
                        .build())
                .setKeyStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(SslContextBuilderIT.class.getResource("/certs/client.jks").getFile())
                        .build())
                .build();
        
        execute(sslContext);
    }

    @Test
    public void clientExecuteRequestShouldNotThrowAnyExceptionWhenClientTrustedAndServerTrusted() throws Exception
    {
        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(SslContextBuilderIT.class.getResource("/certs/client-trust.jks").getFile())
                        .build())
                .setKeyStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(SslContextBuilderIT.class.getResource("/certs/client.jks").getFile())
                        .build())
                .setKeyStorePassword("PtUPmi#o".toCharArray())
                .build();
        
        assertEquals("Ok", execute(sslContext));
    }

    @Test
    public void clientExecuteRequestShouldRequestTrustManagerStrategyWhenServerTrustedClient() throws Exception
    {
        TrustManagerStrategy trustManagerStrategy = mock(TrustManagerStrategy.class);
        when(trustManagerStrategy.checkTrusted(any(X509Certificate[].class), anyString())).thenReturn(true);
        
        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(SslContextBuilderIT.class.getResource("/certs/client-trust.jks").getFile())
                        .build())
                .setTrustManagerStrategy(trustManagerStrategy)
                .setKeyStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(SslContextBuilderIT.class.getResource("/certs/client.jks").getFile())
                        .build())
                .setKeyStorePassword("PtUPmi#o".toCharArray())
                .build();
        
        execute(sslContext);
        
        verify(trustManagerStrategy).checkTrusted(any(X509Certificate[].class), anyString());
    }
    
    @Test
    public void clientExecuteRequestShouldRequestKeyManagerStrategyWhenClientTrustedServer() throws Exception
    {
        KeyManagerStrategy keyManagerStrategy = mock(KeyManagerStrategy.class);
        
        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(SslContextBuilderIT.class.getResource("/certs/client-trust.jks").getFile())
                        .build())
                .setKeyStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(SslContextBuilderIT.class.getResource("/certs/client.jks").getFile())
                        .build())
                .setKeyStorePassword("PtUPmi#o".toCharArray())
                .setKeyManagerStrategy(keyManagerStrategy)
                .build();
        
        execute(sslContext);
        
        verify(keyManagerStrategy).chooseAlias();
    }
}
