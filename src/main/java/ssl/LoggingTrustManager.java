
package ssl;


import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ssl.helper.CertificateHelper;

/**
 * The {@link LoggingTrustManager} delegates all invocation to a given {@link X509TrustManager} and log out the
 * parameter and results.
 * 
 * @author j3t
 */
public class LoggingTrustManager implements X509TrustManager
{
    private X509TrustManager trustManager;
    private Logger logger;

    public LoggingTrustManager(X509TrustManager trustManager)
    {
        this.trustManager = trustManager;
        this.logger = LoggerFactory.getLogger(trustManager.getClass().getName());
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException
    {
        logger.debug("checkClientTrusted(chain, authType) invoked");
        logger.debug("chain contains {} certificate(s)\r\n{}", count(chain), printChain(chain));
        logger.debug("authType is {}", authType);

        try
        {
            trustManager.checkServerTrusted(chain, authType);
            logger.debug("checkClientTrusted(chain, authType) passed");
        }
        catch (CertificateException e)
        {
            logger.error("checkClientTrusted(chain, authType) failed", e);
            throw e;
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException
    {
        logger.debug("checkServerTrusted(chain, authType) invoked");
        logger.debug("chain contains {} certificate(s)\r\n{}", count(chain), printChain(chain));
        logger.debug("authType is {}", authType);

        try
        {
            trustManager.checkServerTrusted(chain, authType);
            logger.debug("checkServerTrusted(chain, authType) passed");
        }
        catch (CertificateException e)
        {
            logger.error("checkServerTrusted(chain, authType) failed", e);
            throw e;
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers()
    {
        logger.debug("getAcceptedIssuers() invoked");
        X509Certificate[] issuers = trustManager.getAcceptedIssuers();

        logger.debug("getAcceptedIssuers() returns {} issuer(s)\r\n{}", count(issuers), printChain(issuers));

        return issuers;
    }

    private String printChain(X509Certificate[] chain)
    {
        if (chain == null)
            return "";

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < chain.length; i++)
        {
            X509Certificate certificate = chain[i];
            sb.append("\t").append(i + 1).append(". ").append(CertificateHelper.printCertificate(certificate));

            if (i < chain.length - 1)
                sb.append("\r\n");
        }

        return sb.toString();
    }

    private int count(Object[] array)
    {
        return array != null ? array.length : 0;
    }

}
