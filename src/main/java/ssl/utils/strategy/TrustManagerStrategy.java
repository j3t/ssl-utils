package ssl.utils.strategy;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * A strategy to establish trustworthiness of certificates independent of the trust manager configured in actual context
 * (trust store). This can be used to override the standard certificate verification process.
 *
 * @author j3t
 *
 */
public interface TrustManagerStrategy
{
    /**
     * Determines whether the certificate chain can be trusted or not or the trust manager configured in the actual
     * context should verify the trustworthiness.
     * 
     * @param chain the peer certificate chain
     * @param authType the authentication type based on the certificate
     * @return <code>true</code> if the trust manager configured in the actual context should verify the
     *         trustworthiness, otherwise <code>false</code>.
     * @throws CertificateException if the certificate chain is not trusted
     */
    boolean checkTrusted(X509Certificate[] chain, String authType) throws CertificateException;
}
