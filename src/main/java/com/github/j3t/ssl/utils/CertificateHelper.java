package com.github.j3t.ssl.utils;


import com.github.j3t.ssl.utils.types.KeyUsage;

import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Helper class to retrieve data from a certificate.
 *
 * @author j3t
 */
public final class CertificateHelper {

    /**
     * Gets the start date of the validity period of the given certificate.
     *
     * @param certificate the given certificate
     * @return the start date of the validity period, or <code>null</code> if the certificate isn't an X.509 certificate
     * @throws IllegalArgumentException if the certificate is <code>null</code>
     */
    public static Date getStartDate(Certificate certificate) {
        checkCertificate(certificate);

        if (X509Certificate.class.isAssignableFrom(certificate.getClass()))
            return ((X509Certificate) certificate).getNotBefore();

        return null;
    }

    /**
     * Gets the end date of the validity period of the given certificate.
     *
     * @param certificate the given certificate
     * @return the end date of the validity period, or <code>null</code> if the certificate isn't an X.509 certificate
     * @throws IllegalArgumentException if the certificate is <code>null</code>
     */
    public static Date getEndDate(Certificate certificate) {
        checkCertificate(certificate);

        if (X509Certificate.class.isAssignableFrom(certificate.getClass()))
            return ((X509Certificate) certificate).getNotAfter();

        return null;
    }

    /**
     * Gets the details (keyUsage, expirationDate, issuer, ...) of the certificate.
     *
     * @param certificate the given certificate
     * @return {@link String}, shouldn't be <code>null</code>
     * @throws IllegalArgumentException if the certificate is <code>null</code>
     */
    public static String getDetails(Certificate certificate) {
        return String.format("keyUsage=%s, expirationDate=%s, issuer=%s",
                Arrays.toString(getKeyUsages(certificate)),
                getEndDate(certificate),
                getIssuer(certificate));
    }

    /**
     * Gets the issuer of the given certificate.
     *
     * @param certificate the certificate
     * @return {@link String} (e.g. CN=DigiCert Assured ID Root G3, OU=www.digicert.com, O=DigiCert Inc, C=US) or an
     * empty String if the certificate isn't a x509 certificate, shouldn't be <code>null</code>
     * @throws IllegalArgumentException if the certificate is <code>null</code> or not an X.509 certificate
     */
    public static String getIssuer(Certificate certificate) {
        if (certificate == null)
            throw new IllegalArgumentException("certificate must not be null!");

        return castToX509CertificateOrThrowException(certificate).getIssuerX500Principal().toString();
    }

    /**
     * Gets the issuers of a given certificate chain.
     *
     * @param certificateChain the certificate
     * @return {@link String} (e.g. CN=DigiCert Assured ID Root G3, OU=www.digicert.com, O=DigiCert Inc, C=US) or an
     * empty String if the certificate isn't a x509 certificate, shouldn't be <code>null</code>
     * @throws IllegalArgumentException if the certificate chain is <code>null</code> or contains at least one non X.509
     *                                  certificate
     */
    public static Collection<String> getIssuers(Certificate[] certificateChain) {
        checkCertificateChain(certificateChain);

        Set<String> issuers = new HashSet<String>();

        for (Certificate certificate : certificateChain)
            issuers.add(getIssuer(certificate));

        return issuers;
    }

    /**
     * Gets the {@link KeyUsage}s of the given certificate.
     *
     * @param certificate the certificate
     * @return array with {@link KeyUsage}-Objects or an empty array if the certificate has not any {@link KeyUsage}s
     * @throws IllegalArgumentException if the certificate is <code>null</code>
     */
    public static KeyUsage[] getKeyUsages(Certificate certificate) {
        List<KeyUsage> supportedKeyUsages = new LinkedList<KeyUsage>();

        for (KeyUsage keyUsage : KeyUsage.values())
            if (isKeyUsagePresent(certificate, keyUsage))
                supportedKeyUsages.add(keyUsage);

        return supportedKeyUsages.toArray(new KeyUsage[supportedKeyUsages.size()]);
    }

    /**
     * Checks that the given certificate has a specific {@link KeyUsage}.
     *
     * @param certificate the given certificate
     * @param keyUsage    the specific {@link KeyUsage}
     * @return <code>true</code> if the certificate has this specific {@link KeyUsage}, otherwise <code>false</code>
     * @throws IllegalArgumentException if the certificate is <code>null</code>
     */
    public static boolean isKeyUsagePresent(Certificate certificate, KeyUsage keyUsage) {
        if (keyUsage == null)
            throw new IllegalArgumentException("keyUsage must not be null!");

        checkCertificate(certificate);

        try {
            X509Certificate x509Certificate = castToX509CertificateOrThrowException(certificate);

            return x509Certificate.getKeyUsage() != null && x509Certificate.getKeyUsage()[keyUsage.ordinal()];
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Checks that a certificate of the given chain has a specific {@link KeyUsage}.
     *
     * @param certificateChain the given certificate chain
     * @param keyUsage         the specific {@link KeyUsage}
     * @return <code>true</code> if at least one certificate has this specific {@link KeyUsage}, otherwise
     * <code>false</code>
     * @throws IllegalArgumentException if the certificate chain is <code>null</code> or contains at least one non X.509
     *                                  certificate
     */
    public static boolean isKeyUsagePresent(Certificate[] certificateChain, KeyUsage keyUsage) {
        checkCertificateChain(certificateChain);

        for (Certificate certificate : certificateChain)
            if (isKeyUsagePresent(certificate, keyUsage))
                return true;

        return false;
    }

    /**
     * Checks that the current time is within the certificate's validity period.
     *
     * @param certificate the given certificate
     * @return <code>true</code> if the certificate is not expired and yet valid, otherwise <code>false</code>
     * @throws IllegalArgumentException if certificate is <code>null</code> or not an X.509 certificate
     */
    public static boolean isValid(Certificate certificate) {
        return isValidAt(certificate, new Date());
    }

    /**
     * Checks that the given time is within the certificate's validity period.
     *
     * @param certificate the certificate
     * @param time        the given time
     * @return <code>true</code> if the certificate is not expired and valid at the given time, otherwise
     * <code>false</code>
     * @throws IllegalArgumentException if certificate or time are <code>null</code> or not an X.509 certificate
     */
    public static boolean isValidAt(Certificate certificate, Date time) {
        if (time == null)
            throw new IllegalArgumentException("time must not be null!");

        X509Certificate x509Certificate = castToX509CertificateOrThrowException(certificate);

        try {
            x509Certificate.checkValidity(time);
        } catch (CertificateExpiredException e) {
            return false;
        } catch (CertificateNotYetValidException e) {
            return false;
        }

        return true;
    }

    /**
     * Casts the given certificate to a {@link X509Certificate}.
     *
     * @param certificate the given certificate
     * @return {@link X509Certificate}, shouldn't be <code>null</code>
     * @throws IllegalArgumentException if certificate is <code>null</code> or not an X.509 certificate
     */
    public static X509Certificate castToX509CertificateOrThrowException(Certificate certificate) {
        checkCertificate(certificate);

        if (!X509Certificate.class.isAssignableFrom(certificate.getClass()))
            throw new IllegalArgumentException("certificate must be an X.509 certificate!");

        return (X509Certificate) certificate;
    }

    /**
     * Checks that the given certificate is not <code>null</code>.
     *
     * @param certificate the given certificate
     * @throws IllegalArgumentException if certificate is <code>null</code>
     */
    public static void checkCertificate(Certificate certificate) {
        if (certificate == null)
            throw new IllegalArgumentException("certificate must not be null!");
    }

    /**
     * Checks that the given certificate chain is not <code>null</code>.
     *
     * @param certificateChain the given certificate chain
     * @throws IllegalArgumentException if certificate chain is <code>null</code>
     */
    public static void checkCertificateChain(Certificate[] certificateChain) {
        if (certificateChain == null)
            throw new IllegalArgumentException("certificate chain must not be null!");
    }
}
