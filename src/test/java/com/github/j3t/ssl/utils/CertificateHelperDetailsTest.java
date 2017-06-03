package com.github.j3t.ssl.utils;

import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CertificateHelperDetailsTest {
    private Calendar start;
    private Calendar end;
    private X509Certificate x509Certificate;
    private Certificate certificate;

    @Before
    public void setUp() throws Exception {
        start = Calendar.getInstance();
        end = Calendar.getInstance();
        x509Certificate = mock(X509Certificate.class);
        certificate = mock(Certificate.class);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getDetailsShouldThrowExceptionWhenCalledWithoutCertificate() {
        CertificateHelper.getDetails(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getDetailsShouldThrowExceptionWhenCertificateIsNotX509() {
        CertificateHelper.getDetails(certificate);
    }

    @Test
    public void getDetailsShouldReturnCommaSeparatedDetailsWhenCertificateIsX509() {
        when(x509Certificate.getSigAlgName()).thenReturn("md5WithRSAEncryption");
        when(x509Certificate.getKeyUsage()).thenReturn(new boolean[]{true, false, false, true, false, false, false, false, false});
        when(x509Certificate.getNotBefore()).thenReturn(start.getTime());
        when(x509Certificate.getNotAfter()).thenReturn(end.getTime());
        when(x509Certificate.getIssuerX500Principal()).thenReturn(new X500Principal("CN=ISSUER"));
        when(x509Certificate.getSubjectX500Principal()).thenReturn(new X500Principal("CN=SUBJECT"));

        String expected = String.format("%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n",
                "Certificate details:",
                "    Signature Algorithm: md5WithRSAEncryption",
                "    KeyUsage: DIGITAL_SIGNATURE, DATA_ENCIPHERMENT",
                "    Validity:",
                "        Not before: " + start.getTime(),
                "        Not after : " + end.getTime(),
                "    Issuer : CN=ISSUER",
                "    Subject: CN=SUBJECT");

        assertEquals(expected, CertificateHelper.getDetails(x509Certificate));
    }

}
