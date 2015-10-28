
package ssl.helper;


import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Comparator;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import ssl.KeyUsage;

public class CertificateHelper
{

    public static boolean isKeyUsageSupported(Certificate cert, KeyUsage keyUsage)
    {
        if (cert instanceof X509Certificate)
        {
            boolean[] keyUsages = ((X509Certificate) cert).getKeyUsage();
            return keyUsages != null && keyUsages[keyUsage.ordinal()];
        }

        return false;
    }

    public static boolean isKeyUsageSupported(Certificate[] certChain, KeyUsage keyUsage)
    {
        for (Certificate cert : certChain)
            if (isKeyUsageSupported(cert, keyUsage))
                return true;
        return false;
    }

    public static Certificate[] sortByLatestExpiration(Certificate[] certificates)
    {
        Arrays.sort(certificates, new Comparator<Certificate>()
        {

            @Override
            public int compare(Certificate o1, Certificate o2)
            {
                Date d1 = CertificateHelper.getExpirationDate(o1);
                Date d2 = CertificateHelper.getExpirationDate(o2);

                return d1 == null && d2 == null ? 0 : (d1 != null ? d1.compareTo(d2) * -1 : d2.compareTo(d1));
            }
        });

        return certificates;
    }

    /**
     * Liefert das Ablaufdatum eines Zertifikats.
     * 
     * @param certificate Das zu prüfende Zertifikat
     * 
     * @return Liefert das Ablaufdatum des {@link X509Certificate} oder <code>null</code>
     */
    public static Date getExpirationDate(Certificate certificate)
    {
        if (certificate instanceof X509Certificate)
            return ((X509Certificate) certificate).getNotAfter();

        return null;
    }

    public static boolean isExpired(Certificate cert)
    {
        Date date = getExpirationDate(cert);

        return date != null && date.before(new Date());
    }

    public static boolean isExpiredIn(Certificate cert, int days)
    {
        if (cert == null)
            return false;
        
        Date date = getExpirationDate(cert);
        
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DAY_OF_MONTH, days);

        return calendar.getTime().after(date);
    }

    public static String printCertificate(Certificate certificate)
    {
        StringBuilder sb = new StringBuilder();

        sb.append("keyUsage=").append(printKeyUsage(certificate));
        sb.append(", expirationDate=").append(getExpirationDate(certificate));
        sb.append(", issuer=").append(printIssuer(certificate));
        
        return sb.toString();
    }

    public static String printIssuer(Certificate certificate)
    {
        if (certificate instanceof X509Certificate)
            return ((X509Certificate) certificate).getIssuerX500Principal().toString();

        return "";
    }

    public static String printKeyUsage(Certificate certificate)
    {
        List<KeyUsage> supportedKeyUsages = new LinkedList<KeyUsage>();

        if (certificate != null)
            for (KeyUsage keyUsage : KeyUsage.values())
                if (CertificateHelper.isKeyUsageSupported(certificate, keyUsage))
                    supportedKeyUsages.add(keyUsage);

        return supportedKeyUsages.toString();
    }

}
