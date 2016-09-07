
package com.github.j3t.ssl.utils;


import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.Random;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.ssl.SslSocketConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.junit.BeforeClass;
import org.junit.Test;

import com.github.j3t.ssl.utils.test.Fixtures;
import com.github.j3t.ssl.utils.types.SslProtocol;

/**
 * @author eexthlr
 */
public class TLS12Test
{
    private static URI uri;

    @BeforeClass
    public static void startServerOnRandomListenerPort() throws Exception
    {
        int port = new Random().nextInt(1024 * 64 - 1 - 1024) + 1024;
        uri = new URI("https", null, "localhost", port, null, null, null);

        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setKeyStore(Fixtures.KEYSTORE_SERVER);
        sslContextFactory.setKeyStorePassword("EC\\sEOoY");
        sslContextFactory.setTrustStore(Fixtures.TRUSTSTORE_SERVER);
        sslContextFactory.setNeedClientAuth(true);
        sslContextFactory.setIncludeProtocols(SslProtocol.TLSv12);

        SslSocketConnector https = new SslSocketConnector(sslContextFactory);
        https.setPort(port);

        Server server = new Server();
        server.addConnector(https);
        server.setStopAtShutdown(true);
        server.setHandler(new AbstractHandler()
            {

                @Override
                public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
                        throws IOException, ServletException
                {
                    response.setStatus(HttpStatus.OK_200);
                    response.getWriter().print("Ok");
                    baseRequest.setHandled(true);
                }
            });
        server.start();
    }

    private String executeRequest() throws Exception
    {
        SSLContext sslContext = SSLContextBuilder.create()
                .setKeyStore(Fixtures.KEYSTORE_CLIENT)
                .setKeyStorePassword("PtUPmi#o")
                .setTrustStore(Fixtures.TRUSTSTORE_CLIENT)
                .build();
        
        HttpsURLConnection conn = (HttpsURLConnection) uri.toURL().openConnection();
        conn.setSSLSocketFactory(sslContext.getSocketFactory());
        InputStream in = conn.getInputStream();

        try
        {
            return new BufferedReader(new InputStreamReader(in)).readLine();
        }
        finally
        {
            in.close();
        }
    }

    @Test
    public void givenClientWithJava7OrHigher_whenRequestExceutedAndServerSupportsTLS12Only_thenRequestShouldBeAnsweredWithOk() throws Exception
    {
        assumeTrue("Java Version isn't 1.7 or higher!", EnvironmentHelper.isJava7OrHigher());

        assertEquals("Ok", executeRequest());
    }
    
    @Test(expected = SSLHandshakeException.class)
    public void givenJavaWithJava6_whenRequestExecutedWithJava6_thenExceptionShouldBeThrown() throws Exception
    {
        assumeTrue("Java Version isn't 1.6!", EnvironmentHelper.isJava6());
        
        executeRequest();
    }
}
