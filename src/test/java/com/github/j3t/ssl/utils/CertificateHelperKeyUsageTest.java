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

public class CertificateHelperKeyUsageTest {
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
    public void getKeyUsagesShouldThrowExceptionWhenCertificateIsNull() {
        CertificateHelper.getKeyUsages(null);
    }

    @Test
    public void getKeyUsagesShouldReturnAnEmptyResultWhenCertificateHasNotAnyKeyUsages() {
        when(x509Certificate.getKeyUsage()).thenReturn(new boolean[]{false, false, false, false, false, false, false, false, false});

        assertArrayEquals(new KeyUsage[0], CertificateHelper.getKeyUsages(x509Certificate));
    }
    
    @Test
    public void getKeyUsagesShouldReturnAllKeyUsagesWhenCertificateHasAllKeyUsages() {
        when(x509Certificate.getKeyUsage()).thenReturn(new boolean[]{true, true, true, true, true, true, true, true, true});

        assertArrayEquals(KeyUsage.values(), CertificateHelper.getKeyUsages(x509Certificate));
    }
    
    @Test
    public void getKeyUsagesShouldReturnOneKeyUsageWhenCertificateHasOnlyOneKeyUsage() {
        when(x509Certificate.getKeyUsage()).thenReturn(new boolean[]{false, false, false, true, false, false, false, false, false});

        assertArrayEquals(new KeyUsage[]{KeyUsage.DATA_ENCIPHERMENT}, CertificateHelper.getKeyUsages(x509Certificate));
    }

    @Test
    public void getKeyUsagesShouldReturnTwoKeyUsagesWhenCertificateHasTwoKeyUsages() {
        when(x509Certificate.getKeyUsage()).thenReturn(new boolean[]{true, false, false, true, false, false, false, false, false});

        assertArrayEquals(new KeyUsage[]{KeyUsage.DIGITAL_SIGNATURE, KeyUsage.DATA_ENCIPHERMENT}, CertificateHelper.getKeyUsages(x509Certificate));
    }

    @Test(expected = IllegalArgumentException.class)
    public void isKeyUsagePresentShouldThrowExceptionCertificateIsNull() {
        CertificateHelper.isKeyUsagePresent((Certificate) null, KeyUsage.DATA_ENCIPHERMENT);
    }

    @Test(expected = IllegalArgumentException.class)
    public void isKeyUsagePresentShouldThrowExceptionWhenCalledWithoutKeyUsage() {
        CertificateHelper.isKeyUsagePresent(x509Certificate, null);
    }

    @Test
    public void isKeyUsagePresentShouldReturnFalseWhenKeyUsageIsNotPresent() {
        when(x509Certificate.getKeyUsage()).thenReturn(new boolean[]{false, false, false, false, false, false, false, false, false});

        assertFalse(CertificateHelper.isKeyUsagePresent(x509Certificate, KeyUsage.DATA_ENCIPHERMENT));
    }

    @Test
    public void isKeyUsagePresentShouldReturnTrueWhenKeyUsageIsPresent() {
        when(x509Certificate.getKeyUsage()).thenReturn(new boolean[]{false, false, false, true, false, false, false, false, false});

        assertTrue(CertificateHelper.isKeyUsagePresent(x509Certificate, KeyUsage.DATA_ENCIPHERMENT));
    }

    @Test
    public void isKeyUsagePresentShouldReturnFalseWhenCertificateInNotAnX509Certificate() {
        assertFalse(CertificateHelper.isKeyUsagePresent(certificate, KeyUsage.DATA_ENCIPHERMENT));
    }

    @Test
    public void isKeyUsagePresentShouldReturnFalseWhenCertificateHasNotAnyKeyUsage() {
        assertFalse(CertificateHelper.isKeyUsagePresent(x509Certificate, KeyUsage.DATA_ENCIPHERMENT));
    }

    @Test(expected = IllegalArgumentException.class)
    public void isKeyUsagePresentShouldThrowExceptionWhenCertificateChainIsNull() {
        CertificateHelper.isKeyUsagePresent((Certificate[]) null, KeyUsage.DATA_ENCIPHERMENT);
    }

}
