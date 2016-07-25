package ssl.utils;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
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

import javax.security.auth.x500.X500Principal;

import org.junit.Before;
import org.junit.Test;

import ssl.utils.CertificateHelper;
import ssl.utils.types.KeyUsage;

public class CertificateHelperTest
{
    private Calendar calendar;
    private X509Certificate certificate;

    @Before
    public void setUp() throws Exception
    {
        calendar = Calendar.getInstance();
        certificate = mock(X509Certificate.class);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void getKeyUsagesShouldThrowExceptionWhenCertificateIsNull()
    {
        CertificateHelper.getKeyUsages(null);
    }
    
    @Test
    public void getKeyUsagesShouldReturnAnEmptyResultWhenCertificateHasNotAnyKeyUsages()
    {
        when(certificate.getKeyUsage()).thenReturn(new boolean[] {false, false, false, false, false, false, false, false, false});

        assertArrayEquals(new KeyUsage[0], CertificateHelper.getKeyUsages(certificate));
    }

    @Test
    public void getKeyUsagesShouldReturnOneKeyUsageWhenCertificateHasOneKeyUsage()
    {
        when(certificate.getKeyUsage()).thenReturn(new boolean[] {false, false, false, true, false, false, false, false, false});

        assertArrayEquals(new KeyUsage[] {KeyUsage.DATA_ENCIPHERMENT}, CertificateHelper.getKeyUsages(certificate));
    }

    @Test
    public void getKeyUsagesShouldReturnTwoKeyUsagesWhenCertificateHasTwoKeyUsages()
    {
        when(certificate.getKeyUsage()).thenReturn(new boolean[] {true, false, false, true, false, false, false, false, false});

        assertArrayEquals(new KeyUsage[] {KeyUsage.DIGITAL_SIGNATURE, KeyUsage.DATA_ENCIPHERMENT}, CertificateHelper.getKeyUsages(certificate));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void getStartDateShouldThrowExceptionWhenCertificateIsNull()
    {
        CertificateHelper.getStartDate(null);
    }
    
    @Test
    public void getStartDateShouldReturnDateWhenCertificateIsAnX509Certificate()
    {
        when(certificate.getNotBefore()).thenReturn(calendar.getTime());
        
        assertEquals(calendar.getTime(), CertificateHelper.getStartDate(certificate));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void getEndDateShouldThrowExceptionWhenCertificateIsNull()
    {
        CertificateHelper.getEndDate(null);
    }
    
    @Test
    public void getEndDateShouldReturnDateWhenCertificateIsAnX509Certificate()
    {
        when(certificate.getNotAfter()).thenReturn(calendar.getTime());
        
        assertEquals(calendar.getTime(), CertificateHelper.getEndDate(certificate));
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
        when(certificate.getIssuerX500Principal()).thenReturn(issuer);
        
        assertEquals("CN=TEST", CertificateHelper.getIssuer(certificate));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void getDetailsShouldThrowExceptionWhenCalledWithoutCertificate()
    {
        CertificateHelper.getDetails(null);
    }
    
    @Test
    public void getDetailsShouldReturnStringWhenCertificateIsAnX509Certificate()
    {
        when(certificate.getKeyUsage()).thenReturn(new boolean[] {true, false, false, true, false, false, false, false, false});
        when(certificate.getNotAfter()).thenReturn(calendar.getTime());
        when(certificate.getIssuerX500Principal()).thenReturn(new X500Principal("CN=TEST"));
        
        assertNotNull(CertificateHelper.getDetails(certificate));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void isKeyUsagePresentShouldThrowExceptionCertificateIsNull()
    {
        CertificateHelper.isKeyUsagePresent((Certificate) null, KeyUsage.DATA_ENCIPHERMENT);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void isKeyUsagePresentShouldThrowExceptionWhenCalledWithoutKeyUsage()
    {
        CertificateHelper.isKeyUsagePresent(certificate, null);
    }

    @Test
    public void isKeyUsagePresentShouldReturnFalseWhenKeyUsageIsNotSupported()
    {
        when(certificate.getKeyUsage()).thenReturn(new boolean[] {false, false, false, false, false, false, false, false, false});
        
        assertFalse(CertificateHelper.isKeyUsagePresent(certificate, KeyUsage.DATA_ENCIPHERMENT));
    }
    
    @Test
    public void isKeyUsagePresentShouldReturnTrueWhenKeyUsageIsSupported()
    {
        when(certificate.getKeyUsage()).thenReturn(new boolean[] {false, false, false, true, false, false, false, false, false});
        
        assertTrue(CertificateHelper.isKeyUsagePresent(certificate, KeyUsage.DATA_ENCIPHERMENT));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void isValidShouldThrowExceptionWhenCalledWithoutCertificate()
    {
        CertificateHelper.isValid(null);
    }

    @Test
    public void isValidShouldReturnFalseWhenCertificateIsNotValidYet() throws Exception
    {
        doThrow(new CertificateNotYetValidException()).when(certificate).checkValidity(any(Date.class));
        
        assertFalse(CertificateHelper.isValid(certificate));
    }
    
    @Test
    public void isValidShouldReturnFalseWhenCertificateIsExpired() throws Exception
    {
        doThrow(new CertificateExpiredException()).when(certificate).checkValidity(any(Date.class));
        
        assertFalse(CertificateHelper.isValid(certificate));
    }
    
    @Test
    public void isValidShouldReturnTrueWhenCertificateIsValid()
    {
        assertTrue(CertificateHelper.isValid(certificate));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void isValidAtShouldThrowExceptionWhenCertificateIsNull()
    {
        CertificateHelper.isValidAt(null, new Date());
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void isValidAtShouldThrowExceptionWhenTimeIsNull()
    {
        CertificateHelper.isValidAt(certificate, null);
    }

    @Test
    public void isValidAtShouldReturnTrueWhenCalledWithValidCertificate()
    {
        when(certificate.getNotAfter()).thenReturn(calendar.getTime());
        calendar.add(Calendar.DAY_OF_MONTH, -1);
        
        assertTrue(CertificateHelper.isValidAt(certificate, calendar.getTime()));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void isValidAtShouldThrowExceptionCalledWithoutTime()
    {
        when(certificate.getNotAfter()).thenReturn(calendar.getTime());
        
        CertificateHelper.isValidAt(certificate, null);
    }
}
