package com.github.j3t.ssl.utils;

import org.junit.Before;
import org.junit.Test;

import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class CertificateHelperValidityTest {
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
    public void getStartDateShouldThrowExceptionWhenCertificateIsNull() {
        CertificateHelper.getValidityStart(null);
    }

    @Test
    public void getStartDateShouldReturnDateWhenCertificateIsAnX509Certificate() {
        when(x509Certificate.getNotBefore()).thenReturn(calendar.getTime());

        assertEquals(calendar.getTime(), CertificateHelper.getValidityStart(x509Certificate));
    }

    @Test
    public void getStartDateShouldReturnNullWhenCertificateIsNotAnX509Certificate() {
        assertNull(CertificateHelper.getValidityStart(certificate));
    }

    @Test(expected = IllegalArgumentException.class)
    public void getEndDateShouldThrowExceptionWhenCertificateIsNull() {
        CertificateHelper.getValidityEnd(null);
    }

    @Test
    public void getEndDateShouldReturnDateWhenCertificateIsAnX509Certificate() {
        when(x509Certificate.getNotAfter()).thenReturn(calendar.getTime());

        assertEquals(calendar.getTime(), CertificateHelper.getValidityEnd(x509Certificate));
    }

    @Test
    public void getEndDateShouldReturnNullWhenCertificateIsNotAnX509Certificate() {
        assertNull(CertificateHelper.getValidityEnd(certificate));
    }


    @Test(expected = IllegalArgumentException.class)
    public void isValidShouldThrowExceptionWhenCalledWithoutCertificate() {
        CertificateHelper.isValid(null);
    }

    @Test
    public void isValidShouldReturnFalseWhenCertificateIsNotValidYet() throws Exception {
        doThrow(new CertificateNotYetValidException()).when(x509Certificate).checkValidity(any(Date.class));

        assertFalse(CertificateHelper.isValid(x509Certificate));
    }

    @Test
    public void isValidShouldReturnFalseWhenCertificateIsExpired() throws Exception {
        doThrow(new CertificateExpiredException()).when(x509Certificate).checkValidity(any(Date.class));

        assertFalse(CertificateHelper.isValid(x509Certificate));
    }

    @Test
    public void isValidShouldReturnTrueWhenCertificateIsValid() {
        assertTrue(CertificateHelper.isValid(x509Certificate));
    }

    @Test(expected = IllegalArgumentException.class)
    public void isValidAtShouldThrowExceptionWhenCertificateIsNull() {
        CertificateHelper.isValidAt(null, new Date());
    }

    @Test(expected = IllegalArgumentException.class)
    public void isValidAtShouldThrowExceptionWhenTimeIsNull() {
        CertificateHelper.isValidAt(x509Certificate, null);
    }

    @Test
    public void isValidAtShouldReturnTrueWhenCalledWithValidCertificate() {
        when(x509Certificate.getNotAfter()).thenReturn(calendar.getTime());
        calendar.add(Calendar.DAY_OF_MONTH, -1);

        assertTrue(CertificateHelper.isValidAt(x509Certificate, calendar.getTime()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void isValidAtShouldThrowExceptionCalledWithoutTime() {
        when(x509Certificate.getNotAfter()).thenReturn(calendar.getTime());

        CertificateHelper.isValidAt(x509Certificate, null);
    }
}
