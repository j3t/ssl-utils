package ssl.helper;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;

import ssl.KeyUsage;
import ssl.helper.CertificateHelper;

public class CertificateHelperTest
{
    private X509Certificate certificate;

    @Before
    public void setUp() throws Exception
    {
        certificate = mock(X509Certificate.class);
    }

    @Test
    public void testIsKeyUsageSupportedWhenKeyUsagesIsNull()
    {
        assertFalse(CertificateHelper.isKeyUsageSupported(certificate, KeyUsage.DATA_ENCIPHERMENT));
    }
    
    @Test
    public void testIsExpiredWithoutCertificate()
    {
        assertFalse(CertificateHelper.isExpired(null));
    }

    @Test
    public void testIsExpiredWithExpiredCertificate()
    {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getNotAfter()).thenReturn(new Date(1));
        
        assertTrue(CertificateHelper.isExpired(cert));
    }
    
    @Test
    public void testIsExpiredWithValidCertificate()
    {
        when(certificate.getNotAfter()).thenReturn(new Date(System.currentTimeMillis() + 10000));
        
        assertFalse(CertificateHelper.isExpired(certificate));
    }
    
    @Test
    public void testIsExpiredInWithoutCertificate()
    {
        assertFalse(CertificateHelper.isExpiredIn(null, 1));
    }

    @Test
    public void testIsExpiredInWithExpiredCertificate()
    {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getNotAfter()).thenReturn(new Date());
        
        assertTrue(CertificateHelper.isExpiredIn(cert, 1));
    }
    
    @Test
    public void testIsExpiredInWithValidCertificate()
    {

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_MONTH, 19);
        
        when(certificate.getNotAfter()).thenReturn(calendar.getTime());
        
        assertTrue(CertificateHelper.isExpiredIn(certificate, 20));
        assertFalse(CertificateHelper.isExpiredIn(certificate, 18));
    }
}
