package ssl.builder;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.security.KeyStore;

import org.junit.Ignore;
import org.junit.Test;

import ssl.builder.KeyStoreBuilder;
import ssl.helper.KeyStoreHelper;

@Ignore("pki card, card reader, itp11 library, pin and JDK7 or above required")
public class KeyStoreBuilderWithItp11IT
{
    @Test
    public void vwPkiCardWithItp11Strict() throws Exception
    {
        KeyStore keyStore = KeyStoreBuilder.create()
        		.setLibraryPath("c:/PROGRA~2/ITSOLU~1/TRUSTW~1.2/32/itp11-strict.dll")
        		.setPassword(("123456".toCharArray()))
        		.build();
        
        assertArrayEquals(new String[]{"ENC"}, KeyStoreHelper.getAliases(keyStore));
    }
    
    @Test
    public void vwPkiCardWithItp11Full() throws Exception
    {
        KeyStore keyStore = KeyStoreBuilder.create()
        		.setLibraryPath("c:/PROGRA~2/ITSOLU~1/TRUSTW~1.2/32/itp11.dll")
        		.build();
        
        assertEquals(3, KeyStoreHelper.getAliases(keyStore).length);
    }
}
