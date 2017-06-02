package com.github.j3t.ssl.utils.strategy;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Implementation of {@link X509TrustManager} that allows control which peers can be trusted. Whenever the
 * trustworthiness of a peer is requested, the given {@link TrustManagerStrategy} will be consulted. Depending on the
 * result, the request will be delegated to the trust manager of the current context or not or an
 * {@link CertificateException} is thrown.
 *
 * @author j3t
 * @see TrustManagerStrategy#checkTrusted(X509Certificate[], String)
 */
public class StrategyTrustManager implements X509TrustManager {
    private X509TrustManager trustManager;
    private TrustManagerStrategy strategy;

    public StrategyTrustManager(X509TrustManager trustManager, TrustManagerStrategy strategy) {
        this.trustManager = trustManager;
        this.strategy = strategy;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (strategy.checkTrusted(chain, authType))
            trustManager.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (strategy.checkTrusted(chain, authType))
            trustManager.checkServerTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return trustManager.getAcceptedIssuers();
    }

}
