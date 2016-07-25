
package com.github.j3t.ssl.utils;


import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.j3t.ssl.utils.types.KeyUsage;

/**
 * Helper class to retrieve data from a key store.
 * 
 * @author j3t
 */
public class KeyStoreHelper
{
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreHelper.class);
    

    /**
     * Returns all aliases from a {@link KeyStore}.
     * 
     * @param keyStore the given {@link KeyStore}
     * 
     * @return {@link String}-Array with aliases (no duplicates) or a an empty array
     * @throws NullPointerException if certificate is <code>null</code>
     */
    public static String[] getAliases(KeyStore keyStore)
    {
        if (keyStore == null)
            throw new NullPointerException("keyStore must not be null!");

        Set<String> aliases = new HashSet<String>();

        try
        {
            Enumeration<String> en = keyStore.aliases();
            while (en.hasMoreElements())
                aliases.add(en.nextElement());
        }
        catch (KeyStoreException e)
        {
            e.printStackTrace();
        }

        return aliases.toArray(new String[aliases.size()]);
    }

    /**
     * Returns all aliases from a {@link KeyStore} with specific key usages.
     * 
     * @param keyStore the given {@link KeyStore}
     * @param keyUsages one or more key usages that must be present
     * @return array of {@link String}s, or an empty array
     * @throws NullPointerException if certificate or keyUsages are <code>null</code>
     */
    public static String[] getAliases(KeyStore keyStore, KeyUsage... keyUsages)
    {
        if (keyUsages == null)
            throw new NullPointerException("keyUsages must not be null!");
        
        if (keyUsages.length == 0)
            return new String[0];
        
        List<String> aliases = new LinkedList<String>(Arrays.asList(getAliases(keyStore)));

        Iterator<String> it = aliases.iterator();
        
        while (it.hasNext())
        {
            try
            {
                Certificate[] certChain = keyStore.getCertificateChain(it.next());

                for (KeyUsage keyUsage : keyUsages)
                    if (!CertificateHelper.isKeyUsagePresent(certChain, keyUsage))
                        it.remove();
            }
            catch (KeyStoreException e)
            {
                LOGGER.warn("getAliases raised exception", e);
            }
        }

        return aliases.toArray(new String[aliases.size()]);
    }

    /**
     * Returns a human readable representation of a {@link KeyStore}.
     * 
     * @param keyStore the given {@link KeyStore}
     * @return {@link String}, shouldn't be <code>null</code>
     */
    public static String toString(KeyStore keyStore)
    {
        StringBuilder sb = new StringBuilder();

        String[] aliases = getAliases(keyStore);

        if (aliases == null || aliases.length == 0)
        {
            sb.append("keyStore is empty");
        }
        else
        {
            sb.append("keyStore contains ").append(aliases.length).append(" aliase(s)").append("\r\n");
            sb.append(toStringByAlias(keyStore, aliases));
        }

        return sb.toString();
    }

    /**
     * Returns a human readable representation of the aliases from a given keystore.
     * 
     * @param keyStore the given {@link KeyStore}
     * @param aliases the given aliases
     * @return {@link String}, shouldn't be <code>null</code>
     */
    public static String toStringByAlias(KeyStore keyStore, String... aliases)
    {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < aliases.length; i++)
        {
            String alias = aliases[i];

            sb.append("\t").append(i + 1).append(". ").append(alias).append(" - ");
            try
            {
                Certificate certificate = keyStore.getCertificate(alias);
                String certToString = CertificateHelper.getDetails(certificate);
                sb.append(certToString);
            }
            catch (KeyStoreException e)
            {
                e.printStackTrace();
            }

            if (i < aliases.length - 1) sb.append("\r\n");
        }

        return sb.toString();
    }

}
