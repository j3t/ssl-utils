package ssl.utils.strategy;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * Implementation of {@link X509TrustManager} that allows control which peers can be trusted. Whenever the
 * trustworthiness of a peer is requested, the given {@link TrustManagerStrategy} will be consulted. Depending on the
 * result, the request will be delegated to the trust manager of the current context or not or an
 * {@link CertificateException} is thrown.
 * 
 * @see TrustManagerStrategy#checkTrusted(X509Certificate[], String)
 *
 * @author j3t
 *
 */
public class FilterTrustManager implements X509TrustManager
{
    private X509TrustManager trustManager;
    private TrustManagerStrategy trustManagerStrategy;

    public FilterTrustManager(X509TrustManager trustManager, TrustManagerStrategy trustManagerStrategy)
    {
        this.trustManager = trustManager;
        this.trustManagerStrategy = trustManagerStrategy;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException
    {
        if (trustManagerStrategy.checkTrusted(chain, authType))
            trustManager.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException
    {
        if (trustManagerStrategy.checkTrusted(chain, authType))
            trustManager.checkServerTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers()
    {
        return trustManager.getAcceptedIssuers();
    }

}
