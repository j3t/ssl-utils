package ssl.builder;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static ssl.KeyStoreType.PKCS11;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Security;

import org.junit.Ignore;
import org.junit.Test;

import ssl.helper.KeyStoreHelper;

@Ignore("pki card, card reader, itp11 library, pin and JDK7 or above required")
public class KeyStoreBuilderWithPKCS11IT
{
    @Test
    public void vwPkiCardWithItp11Strict() throws Exception
    {
        KeyStore keyStore = KeyStoreBuilder.create()
        		.setType(PKCS11)
        		.setLibraryPath("c:/PROGRA~2/ITSOLU~1/TRUSTW~1.2/32/itp11-strict.dll")
        		.setPassword(("123456".toCharArray()))
        		.build();
        
        assertArrayEquals(new String[]{"ENC"}, KeyStoreHelper.getAliases(keyStore));
    }
    
    @Test
    public void vwPkiCardWithItp11Full() throws Exception
    {
        KeyStore keyStore = KeyStoreBuilder.create()
        		.setType(PKCS11)
        		.setLibraryPath("c:/PROGRA~2/ITSOLU~1/TRUSTW~1.2/32/itp11.dll")
        		.build();
        
        assertEquals(3, KeyStoreHelper.getAliases(keyStore).length);
    }
    
    @Test
    public void vwPkiCardWithRegisteredProvider() throws Exception
    {
    	 String config = new StringBuilder()
		 		.append("name = ").append("CustomProvider").append("\n")
		 		.append("library = ").append("c:/PROGRA~2/ITSOLU~1/TRUSTW~1.2/32/itp11.dll").append("\n")
		 		.toString();

    	InputStream inputStream = new ByteArrayInputStream(config.getBytes());

 		@SuppressWarnings("restriction")
 		sun.security.pkcs11.SunPKCS11 p = new sun.security.pkcs11.SunPKCS11(inputStream);
 		Security.addProvider(p);
    	
        KeyStore keyStore = KeyStoreBuilder.create()
        		.setType(PKCS11)
        		.setProvider("SunPKCS11-CustomProvider")
        		.build();
        
        assertEquals(3, KeyStoreHelper.getAliases(keyStore).length);
    }
}
