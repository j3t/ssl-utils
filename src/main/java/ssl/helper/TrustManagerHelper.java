
package ssl.helper;


import java.security.KeyStore;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ssl.AllowAllTrustManager;
import ssl.KeyStoreProvider;
import ssl.KeyStoreType;
import ssl.LoggingTrustManager;

/**
 * {@link TrustManagerHelper} provides factory methods for some common {@link TrustManager} implementation.
 * 
 * @author EEXTHLR
 */
public class TrustManagerHelper
{
    private static final Logger LOGGER = LoggerFactory.getLogger(TrustManagerHelper.class);

    /**
     * Creates the allow all {@link TrustManager}s.
     *
     * @see AllowAllTrustManager
     * 
     * @return Array with one {@link TrustManager}
     */
    public static TrustManager[] createAllowAllTrustManagers()
    {
        return new TrustManager[] {new AllowAllTrustManager()};
    }

    /**
     * Creates the Windows-My KeyStore and returns the {@link TrustManager}s.
     * 
     * @return Array with {@link TrustManager}s, or an empty array
     */
    public static TrustManager[] createWindowsMyTrustManagers()
    {
        try
        {
            KeyStore trustStore = KeyStore.getInstance(KeyStoreType.WINDOWS_MY, KeyStoreProvider.SUNMSCAPI);
            trustStore.load(null, null);

            String defaultAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory instance = TrustManagerFactory.getInstance(defaultAlgorithm);
            instance.init(trustStore);

            return instance.getTrustManagers();
        }
        catch (Exception e)
        {
            LOGGER.error("createWindowsMyTrustManagers failed!", e);
            return new TrustManager[0];
        }
    }
    
    /**
     * Creates the Windows-My KeyStore and returns the {@link TrustManager}s.
     * 
     * @return Array with {@link TrustManager}s, or an empty array
     */
    public static TrustManager[] createWindowsRootTrustManagers()
    {
        try
        {
            KeyStore trustStore = KeyStore.getInstance(KeyStoreType.WINDOWS_ROOT, KeyStoreProvider.SUNMSCAPI);
            trustStore.load(null, null);

            String defaultAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory instance = TrustManagerFactory.getInstance(defaultAlgorithm);
            instance.init(trustStore);

            return instance.getTrustManagers();
        }
        catch (Exception e)
        {
            LOGGER.error("createWindowsRootTrustManagers failed!", e);
            return new TrustManager[0];
        }
    }
    
    /**
     * Proxy of a given array of {@link TrustManager} for logging purposes.
     * 
     * @param trustManagers the array of given {@link TrustManager}s
     * @return array of the same size and the same behavior, but with logging informations
     */
    public static TrustManager[] proxyWithLoggingTrustManager(TrustManager[] trustManagers)
    {
        TrustManager[] tms = new TrustManager[trustManagers.length];

        for (int i = 0; i < trustManagers.length; i++)
        {
            TrustManager trustManager = trustManagers[i];
            if (trustManager instanceof X509TrustManager)
                tms[i] = new LoggingTrustManager((X509TrustManager) trustManager);
            else
                tms[i] = trustManager;
        }

        return tms;
    }
}
