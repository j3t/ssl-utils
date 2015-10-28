/*
 * EasyTrustManager.java
 * 
 * Created on 09.05.2012
 * 
 * Copyright (C) 2012 Volkswagen AG, All rights reserved.
 */

package ssl;


import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * {@link AllowAllTrustManager} is a no-op implementation of the {@link X509TrustManager}. This means, that <b>all</b>
 * clients and servers are trusted.
 * 
 * @author j3t
 * 
 */
public class AllowAllTrustManager implements X509TrustManager
{

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException
    {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException
    {
    }
    
    @Override
    public X509Certificate[] getAcceptedIssuers()
    {
        return null;
    }

}
