package com.github.j3t.ssl.utils;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;

import javax.security.auth.x500.X500Principal;

import org.junit.Before;
import org.junit.Test;

import com.github.j3t.ssl.utils.types.KeyUsage;

public class CertificateHelperTest
{
    private Calendar calendar;
    private X509Certificate x509Certificate;
    private Certificate certificate;

    @Before
    public void setUp() throws Exception
    {
        calendar = Calendar.getInstance();
        x509Certificate = mock(X509Certificate.class);
        certificate = mock(Certificate.class);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void getKeyUsagesShouldThrowExceptionWhenCertificateIsNull()
    {
        CertificateHelper.getKeyUsages(null);
    }
    
    @Test
    public void getKeyUsagesShouldReturnAnEmptyResultWhenCertificateHasNotAnyKeyUsages()
    {
        when(x509Certificate.getKeyUsage()).thenReturn(new boolean[] {false, false, false, false, false, false, false, false, false});

        assertArrayEquals(new KeyUsage[0], CertificateHelper.getKeyUsages(x509Certificate));
    }

    @Test
    public void getKeyUsagesShouldReturnOneKeyUsageWhenCertificateHasOneKeyUsage()
    {
        when(x509Certificate.getKeyUsage()).thenReturn(new boolean[] {false, false, false, true, false, false, false, false, false});

        assertArrayEquals(new KeyUsage[] {KeyUsage.DATA_ENCIPHERMENT}, CertificateHelper.getKeyUsages(x509Certificate));
    }

    @Test
    public void getKeyUsagesShouldReturnTwoKeyUsagesWhenCertificateHasTwoKeyUsages()
    {
        when(x509Certificate.getKeyUsage()).thenReturn(new boolean[] {true, false, false, true, false, false, false, false, false});

        assertArrayEquals(new KeyUsage[] {KeyUsage.DIGITAL_SIGNATURE, KeyUsage.DATA_ENCIPHERMENT}, CertificateHelper.getKeyUsages(x509Certificate));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void getStartDateShouldThrowExceptionWhenCertificateIsNull()
    {
        CertificateHelper.getStartDate(null);
    }
    
    @Test
    public void getStartDateShouldReturnDateWhenCertificateIsAnX509Certificate()
    {
        when(x509Certificate.getNotBefore()).thenReturn(calendar.getTime());
        
        assertEquals(calendar.getTime(), CertificateHelper.getStartDate(x509Certificate));
    }
    
    @Test
    public void getStartDateShouldReturnNullWhenCertificateIsNotAnX509Certificate()
    {
        assertNull(CertificateHelper.getStartDate(certificate));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void getEndDateShouldThrowExceptionWhenCertificateIsNull()
    {
        CertificateHelper.getEndDate(null);
    }
    
    @Test
    public void getEndDateShouldReturnDateWhenCertificateIsAnX509Certificate()
    {
        when(x509Certificate.getNotAfter()).thenReturn(calendar.getTime());
        
        assertEquals(calendar.getTime(), CertificateHelper.getEndDate(x509Certificate));
    }
    
    @Test
    public void getEndDateShouldReturnNullWhenCertificateIsNotAnX509Certificate()
    {
        assertNull(CertificateHelper.getEndDate(certificate));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void getIssuerShouldThrowExceptionWhenCalledWithoutCertificate()
    {
        CertificateHelper.getIssuer(null);
    }
    
    @Test
    public void getIssuerShouldReturnStringWhenCalledWithCertificate()
    {
        X500Principal issuer = new X500Principal("CN=TEST");
        when(x509Certificate.getIssuerX500Principal()).thenReturn(issuer);
        
        assertEquals("CN=TEST", CertificateHelper.getIssuer(x509Certificate));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void getIssuersShouldThrowExceptionWhenCalledWithoutCertificate()
    {
        CertificateHelper.getIssuers(null);
    }
    
    @Test
    public void getIssuersShouldReturnOneStringWhenCalledWithOneCertificate()
    {
        X500Principal issuer = new X500Principal("CN=TEST");
        when(x509Certificate.getIssuerX500Principal()).thenReturn(issuer);
        
        Iterator<String> issuers = CertificateHelper.getIssuers(new Certificate[]{x509Certificate}).iterator();
        
		assertEquals("CN=TEST", issuers.next());
		assertFalse(issuers.hasNext());
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void getDetailsShouldThrowExceptionWhenCalledWithoutCertificate()
    {
        CertificateHelper.getDetails(null);
    }
    
    @Test
    public void getDetailsShouldReturnStringWhenCertificateIsAnX509Certificate()
    {
        when(x509Certificate.getKeyUsage()).thenReturn(new boolean[] {true, false, false, true, false, false, false, false, false});
        when(x509Certificate.getNotAfter()).thenReturn(calendar.getTime());
        when(x509Certificate.getIssuerX500Principal()).thenReturn(new X500Principal("CN=TEST"));
        
        assertNotNull(CertificateHelper.getDetails(x509Certificate));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void isKeyUsagePresentShouldThrowExceptionCertificateIsNull()
    {
        CertificateHelper.isKeyUsagePresent((Certificate) null, KeyUsage.DATA_ENCIPHERMENT);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void isKeyUsagePresentShouldThrowExceptionWhenCalledWithoutKeyUsage()
    {
        CertificateHelper.isKeyUsagePresent(x509Certificate, null);
    }

    @Test
    public void isKeyUsagePresentShouldReturnFalseWhenKeyUsageIsNotPresent()
    {
        when(x509Certificate.getKeyUsage()).thenReturn(new boolean[] {false, false, false, false, false, false, false, false, false});
        
        assertFalse(CertificateHelper.isKeyUsagePresent(x509Certificate, KeyUsage.DATA_ENCIPHERMENT));
    }
    
    @Test
    public void isKeyUsagePresentShouldReturnTrueWhenKeyUsageIsPresent()
    {
        when(x509Certificate.getKeyUsage()).thenReturn(new boolean[] {false, false, false, true, false, false, false, false, false});
        
        assertTrue(CertificateHelper.isKeyUsagePresent(x509Certificate, KeyUsage.DATA_ENCIPHERMENT));
    }
    
    @Test
    public void isKeyUsagePresentShouldReturnFalseWhenCertificateInNotAnX509Certificate()
    {
        assertFalse(CertificateHelper.isKeyUsagePresent(certificate, KeyUsage.DATA_ENCIPHERMENT));
    }
    
    @Test
    public void isKeyUsagePresentShouldReturnFalseWhenCertificateHasNotAnyKeyUsage()
    {
        assertFalse(CertificateHelper.isKeyUsagePresent(x509Certificate, KeyUsage.DATA_ENCIPHERMENT));
    }
    
    
    @Test(expected = IllegalArgumentException.class)
    public void isValidShouldThrowExceptionWhenCalledWithoutCertificate()
    {
        CertificateHelper.isValid(null);
    }

    @Test
    public void isValidShouldReturnFalseWhenCertificateIsNotValidYet() throws Exception
    {
        doThrow(new CertificateNotYetValidException()).when(x509Certificate).checkValidity(any(Date.class));
        
        assertFalse(CertificateHelper.isValid(x509Certificate));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void isKeyUsagePresentShouldThrowExceptionWhenCertificateChainIsNull()
    {
        CertificateHelper.isKeyUsagePresent((Certificate[]) null, KeyUsage.DATA_ENCIPHERMENT);
    }
    
    @Test
    public void isValidShouldReturnFalseWhenCertificateIsExpired() throws Exception
    {
        doThrow(new CertificateExpiredException()).when(x509Certificate).checkValidity(any(Date.class));
        
        assertFalse(CertificateHelper.isValid(x509Certificate));
    }
    
    @Test
    public void isValidShouldReturnTrueWhenCertificateIsValid()
    {
        assertTrue(CertificateHelper.isValid(x509Certificate));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void isValidAtShouldThrowExceptionWhenCertificateIsNull()
    {
        CertificateHelper.isValidAt(null, new Date());
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void isValidAtShouldThrowExceptionWhenTimeIsNull()
    {
        CertificateHelper.isValidAt(x509Certificate, null);
    }

    @Test
    public void isValidAtShouldReturnTrueWhenCalledWithValidCertificate()
    {
        when(x509Certificate.getNotAfter()).thenReturn(calendar.getTime());
        calendar.add(Calendar.DAY_OF_MONTH, -1);
        
        assertTrue(CertificateHelper.isValidAt(x509Certificate, calendar.getTime()));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void isValidAtShouldThrowExceptionCalledWithoutTime()
    {
        when(x509Certificate.getNotAfter()).thenReturn(calendar.getTime());
        
        CertificateHelper.isValidAt(x509Certificate, null);
    }
    
}
