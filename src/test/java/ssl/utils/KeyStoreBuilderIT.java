
package ssl.utils;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.security.UnrecoverableKeyException;
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

import ssl.utils.types.KeyStoreType;

public class KeyStoreBuilderIT
{
    private static Server server;
    private static URI request;

    @BeforeClass
    public static void setUpClass() throws Exception
    {
        int port = new Random().nextInt(1024 * 64 - 1 - 1024) + 1024;
        
        request = new URI("https", null, "localhost", port, null, null, null);
        server = new Server();

        SslContextFactory sslContextFactory = new SslContextFactory();
        sslContextFactory.setKeyStorePath(KeyStoreBuilderIT.class.getResource("/server.jks").getFile());
        sslContextFactory.setKeyStorePassword("EC\\sEOoY");
        sslContextFactory.setTrustStorePath(KeyStoreBuilderIT.class.getResource("/server-trust.jks").getFile());
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

    private void execute(SSLContext sslContext, URL url) throws IOException
    {
        BufferedReader in = null;
        try
        {
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslContext.getSocketFactory());
            
            in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            
            while (in.readLine() != null);
        }
        catch (IOException e)
        {
            throw e;
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
        
        execute(sslContext, request.toURL());
    }

    @Test(expected = SSLHandshakeException.class)
    public void clientExecuteRequestShouldThrowExceptionWhenClientUnknownAndServerTrusted() throws Exception
    {
        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(KeyStoreBuilderIT.class.getResource("/client-trust.jks").getFile())
                        .build())
                .build();
        
        execute(sslContext, request.toURL());
    }

    @Test(expected = SSLHandshakeException.class)
    public void clientExecuteRequestShouldThrowExceptionWhenClientNotTrustedAndServerTrusted() throws Exception
    {
        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(KeyStoreBuilderIT.class.getResource("/client-trust.jks").getFile())
                        .build())
                .setKeyStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(KeyStoreBuilderIT.class.getResource("/unknown-client.jks").getFile())
                        .build())
                .setKeyStorePassword("changeit".toCharArray())
                .build();
        
        execute(sslContext, request.toURL());
    }
    
    @Test(expected = UnrecoverableKeyException.class)
    public void clientExecuteRequestShouldThrowExceptionWhenKeyStorePasswordIsNotProvided() throws Exception
    {
        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(KeyStoreBuilderIT.class.getResource("/client-trust.jks").getFile())
                        .build())
                .setKeyStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(KeyStoreBuilderIT.class.getResource("/client.jks").getFile())
                        .build())
                .build();
        
        execute(sslContext, request.toURL());
    }

    @Test
    public void clientExecuteRequestShouldNotThrowAnyExceptionWhenClientTrustedAndServerTrusted() throws Exception
    {
        SSLContext sslContext = SSLContextBuilder.create()
                .setTrustStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(KeyStoreBuilderIT.class.getResource("/client-trust.jks").getFile())
                        .build())
                .setKeyStore(KeyStoreBuilder.create()
                        .setType(KeyStoreType.JKS)
                        .setPath(KeyStoreBuilderIT.class.getResource("/client.jks").getFile())
                        .build())
                .setKeyStorePassword("PtUPmi#o".toCharArray())
                .build();
        
        execute(sslContext, request.toURL());
    }

}
