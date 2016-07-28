package com.github.j3t.ssl.utils.strategy;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import javax.net.ssl.X509KeyManager;

import org.junit.Before;
import org.junit.Test;

public class StrategyKeyManagerTest
{
    private X509KeyManager delegate;
    private StrategyKeyManager keyManager;
    private KeyManagerStrategy strategy;

    @Before
    public void setUp() throws Exception
    {
        delegate = mock(X509KeyManager.class);
        strategy = mock(KeyManagerStrategy.class);
        keyManager = new StrategyKeyManager(delegate, strategy);
    }

    @Test
    public void chooseClientAliasShouldConsultDelegateWhenStrategyReturnedNull()
    {
        keyManager.chooseClientAlias(null, null, null);
        
        verify(delegate).chooseClientAlias(null, null, null);
    }
    
    @Test
    public void chooseClientAliasShouldNotConsultDelegateWhenStrategyReturnedNotNull()
    {
        when(strategy.chooseAlias()).thenReturn("client");
        keyManager.chooseClientAlias(null, null, null);
        
        verifyZeroInteractions(delegate);
    }
    
    @Test
    public void chooseServerAliasShouldConsultDelegateWhenStrategyReturnedNull()
    {
        keyManager.chooseServerAlias(null, null, null);
        
        verify(delegate).chooseServerAlias(null, null, null);
    }
    
    @Test
    public void chooseServerAliasShouldNotConsultDelegateWhenStrategyReturnedNotNull()
    {
        when(strategy.chooseAlias()).thenReturn("client");
        keyManager.chooseServerAlias(null, null, null);
        
        verifyZeroInteractions(delegate);
    }

    @Test
    public void getCertificateChainShouldConsultDelegateEveryTime()
    {
        keyManager.getCertificateChain("client");
        
        verify(delegate).getCertificateChain("client");
    }

    @Test
    public void getClientAliasesShouldConsultDelegateEveryTime()
    {
        keyManager.getClientAliases(null, null);
        
        verify(delegate).getClientAliases(null, null);
    }

    @Test
    public void getPrivateKeyShouldConsultDelegateEveryTime()
    {
        keyManager.getPrivateKey("client");
        
        verify(delegate).getPrivateKey("client");
    }

    @Test
    public void getServerAliasesShouldConsultDelegateEveryTime()
    {
        keyManager.getServerAliases(null, null);
        
        verify(delegate).getServerAliases(null, null);
    }

}
