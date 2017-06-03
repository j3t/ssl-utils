package com.github.j3t.ssl.utils;

import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Iterator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CertificateHelperSubjectTest {
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
    public void getSubjectShouldThrowExceptionWhenCertificateIsNull() {
        CertificateHelper.getSubject(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getSubjectShouldThrowExceptionWhenCertificateStandardIsNotX509() {
        CertificateHelper.getSubject(certificate);
    }

    @Test
    public void getSubjectShouldReturnSubjectNameWhenCertificateIsNotNull() {
        when(x509Certificate.getSubjectX500Principal()).thenReturn(new X500Principal("CN=TEST"));

        assertEquals("CN=TEST", CertificateHelper.getSubject(x509Certificate));
    }

    @Test(expected = IllegalArgumentException.class)
    public void getSubjectsShouldThrowExceptionWhenCertificateIsNull() {
        CertificateHelper.getSubject(null);
    }

}
