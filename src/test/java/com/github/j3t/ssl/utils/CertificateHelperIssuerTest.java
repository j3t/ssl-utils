package com.github.j3t.ssl.utils;

import com.github.j3t.ssl.utils.types.KeyUsage;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class CertificateHelperIssuerTest {
    private Calendar calendar;
    private X509Certificate x509Certificate;
    private Certificate certificate;

    @Before
    public void setUp() throws Exception {
        calendar = Calendar.getInstance();
        x509Certificate = mock(X509Certificate.class);
        certificate = mock(Certificate.class);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getIssuerShouldThrowExceptionWhenCertificateIsNull() {
        CertificateHelper.getIssuer(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getIssuerShouldThrowExceptionWhenCertificateStandardIsNotX509() {
        CertificateHelper.getIssuer(certificate);
    }

    @Test
    public void getIssuerShouldReturnIssuerNameWhenCertificateIsNotNull() {
        when(x509Certificate.getIssuerX500Principal()).thenReturn(new X500Principal("CN=TEST"));

        assertEquals("CN=TEST", CertificateHelper.getIssuer(x509Certificate));
    }

    @Test(expected = IllegalArgumentException.class)
    public void getIssuersShouldThrowExceptionWhenCertificateIsNull() {
        CertificateHelper.getIssuers(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getIssuersShouldThrowExceptionWhenCertificateStandardIsNotX509() {
        CertificateHelper.getIssuers(new Certificate[] {certificate});
    }

    @Test
    public void getIssuersShouldReturnAllIssuerNamesWhenCertificatesAreNotEmpty() {
        when(x509Certificate.getIssuerX500Principal()).thenReturn(new X500Principal("CN=TEST"));

        Iterator<String> issuers = CertificateHelper.getIssuers(new Certificate[]{x509Certificate}).iterator();

        assertEquals("CN=TEST", issuers.next());
        assertFalse(issuers.hasNext());
    }

}
