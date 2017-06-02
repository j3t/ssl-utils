package com.github.j3t.ssl.utils;


import com.github.j3t.ssl.utils.types.KeyUsage;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.*;

/**
 * Helper class to retrieve data from a key store.
 *
 * @author j3t
 */
public final class KeyStoreHelper {

    /**
     * Returns all aliases from a {@link KeyStore}.
     *
     * @param keyStore the given {@link KeyStore}
     * @return {@link String}-Array with aliases (no duplicates) or a an empty array
     * @throws IllegalArgumentException if keyStore is <code>null</code>
     * @throws IllegalStateException    if the KeyStore is not been initialized
     */
    public static String[] getAliases(KeyStore keyStore) {
        checkKeyStore(keyStore);

        Set<String> aliases = new HashSet<String>();

        try {
            Enumeration<String> en = keyStore.aliases();
            while (en.hasMoreElements())
                aliases.add(en.nextElement());
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }

        return aliases.toArray(new String[aliases.size()]);
    }

    /**
     * Returns all aliases from a {@link KeyStore} with specific key usages.
     *
     * @param keyStore  the given {@link KeyStore}
     * @param keyUsages one or more key usages that must be present
     * @return array of {@link String}s, or an empty array
     * @throws IllegalArgumentException if keyStore or keyUsages are <code>null</code>
     * @throws IllegalStateException    if the KeyStore is not been initialized
     */
    public static String[] getAliases(KeyStore keyStore, KeyUsage... keyUsages) {
        checkKeyStore(keyStore);

        if (keyUsages == null)
            throw new IllegalArgumentException("keyUsages must not be null!");

        if (keyUsages.length == 0)
            return new String[0];

        try {
            List<String> aliases = new LinkedList<String>();
            Enumeration<String> en = keyStore.aliases();

            while (en.hasMoreElements()) {
                String alias = en.nextElement();
                aliases.add(alias);
                Certificate[] certChain = keyStore.getCertificateChain(alias);

                for (KeyUsage keyUsage : keyUsages)
                    if (!CertificateHelper.isKeyUsagePresent(certChain, keyUsage))
                        aliases.remove(alias);
            }

            return aliases.toArray(new String[aliases.size()]);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns a human readable representation of a {@link KeyStore}.
     *
     * @param keyStore the given {@link KeyStore}
     * @return {@link String}, shouldn't be <code>null</code>
     * @throws IllegalArgumentException if keyStore is <code>null</code>
     * @throws IllegalStateException    if the KeyStore is not been initialized
     */
    public static String toString(KeyStore keyStore) {
        String[] aliases = getAliases(keyStore);

        if (aliases.length == 0)
            return "keyStore is empty";

        return String.format("keyStore contains %d aliase(s)\r\n%s", aliases.length, toStringByAlias(keyStore, aliases));
    }

    /**
     * Returns a human readable representation of the aliases from a given key store.
     *
     * @param keyStore the given {@link KeyStore}
     * @param aliases  the given aliases
     * @return {@link String}, shouldn't be <code>null</code>
     * @throws IllegalArgumentException if keyStore is <code>null</code>
     * @throws IllegalStateException    if the KeyStore is not been initialized
     */
    public static String toStringByAlias(KeyStore keyStore, String... aliases) {
        checkKeyStore(keyStore);

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < aliases.length; i++) {
            if (i > 0)
                sb.append("\r\n");

            String alias = aliases[i];

            sb.append("\t").append(i + 1).append(". ").append(alias).append(" - ");
            try {
                Certificate certificate = keyStore.getCertificate(alias);
                String certToString = CertificateHelper.getDetails(certificate);
                sb.append(certToString);
            } catch (KeyStoreException e) {
                throw new IllegalStateException(e);
            }
        }

        return sb.toString();
    }

    /**
     * Checks that the given key store isn't <code>null</code>.
     *
     * @param keyStore the given {@link KeyStore}
     * @throws IllegalArgumentException if the key store <code>null</code>
     */
    public static void checkKeyStore(KeyStore keyStore) {
        if (keyStore == null)
            throw new IllegalArgumentException("keyStore must not be null!");
    }

}
