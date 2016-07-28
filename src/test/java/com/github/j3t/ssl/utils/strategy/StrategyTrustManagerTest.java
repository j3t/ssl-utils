package com.github.j3t.ssl.utils.strategy;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import java.security.cert.CertificateException;

import javax.net.ssl.X509TrustManager;

import org.junit.Before;
import org.junit.Test;

public class StrategyTrustManagerTest
{
    private X509TrustManager delegate;
    private X509TrustManager keyManager;
    private TrustManagerStrategy strategy;

    @Before
    public void setUp() throws Exception
    {
        delegate = mock(X509TrustManager.class);
        strategy = mock(TrustManagerStrategy.class);
        keyManager = new StrategyTrustManager(delegate, strategy);
    }

    @Test
    public void checkClientTrustedShouldConsultDelegateWhenStrategyReturnedTrue() throws CertificateException
    {
        when(strategy.checkTrusted(null, null)).thenReturn(true);
        keyManager.checkClientTrusted(null, null);
        
        verify(delegate).checkClientTrusted(null, null);
    }
    
    @Test
    public void checkClientTrustedShouldNotConsultDelegateWhenStrategyReturnedFalse() throws CertificateException
    {
        keyManager.checkClientTrusted(null, null);
        
        verifyZeroInteractions(delegate);
    }

    @Test
    public void checkServerTrustedShouldConsultDelegateWhenStrategyReturnedTrue() throws CertificateException
    {
        when(strategy.checkTrusted(null, null)).thenReturn(true);
        keyManager.checkServerTrusted(null, null);
        
        verify(delegate).checkServerTrusted(null, null);
    }
    
    @Test
    public void checkServerTrustedShouldNotConsultDelegateWhenStrategyReturnedFalse() throws CertificateException
    {
        keyManager.checkServerTrusted(null, null);
        
        verifyZeroInteractions(delegate);
    }

    @Test
    public void getAcceptedIssuersShouldConsultDelegateEveryTime() throws Exception
    {
        keyManager.getAcceptedIssuers();
        
        verify(delegate).getAcceptedIssuers();
    }
}
