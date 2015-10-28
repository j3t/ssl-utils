
package ssl.strategy;


import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.X509KeyManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StrategyKeyManager implements X509KeyManager
{
    private X509KeyManager keyManager;
    private AliasSelectionStrategy aliasStrategy;
    private Logger logger;

    public StrategyKeyManager(X509KeyManager keyManager, AliasSelectionStrategy aliasStrategy)
    {
        this.keyManager = keyManager;
        this.aliasStrategy = aliasStrategy;
        this.logger = LoggerFactory.getLogger(keyManager.getClass());
    }

    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket)
    {
        logger.debug("chooseClientAlias(keyTypes, issuers, socket) invoked");
        logger.debug("keyTypes are {}", Arrays.toString(keyTypes));
        logger.debug("issuers contains {} issuer(s)\r\n{}", count(issuers), printObjects(issuers));
        logger.debug("socket is {}", socket);
        
        String alias = this.aliasStrategy.getSelection();
        logger.debug("selected alias is {}", alias == null ? "empty" : alias);
        
        if (alias == null || alias.isEmpty())
            alias = keyManager.chooseClientAlias(keyTypes, issuers, socket);

        logger.debug("used alias is {}", alias);
        
        return alias;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket)
    {
        logger.debug("chooseServerAlias(keyType, issuers, socket) invoked");
        logger.debug("keyType is {}", keyType);
        logger.debug("issuers contains {} issuer\r\n{}", count(issuers), printObjects(issuers));
        logger.debug("socket is {}", socket);
        
        String alias = this.aliasStrategy.getSelection();
        logger.debug("selected alias is {}", alias);

        if (alias == null)
            alias = keyManager.chooseServerAlias(keyType, issuers, socket);

        logger.debug("used alias is {}", alias);
        
        return alias;
    }

    @Override
    public X509Certificate[] getCertificateChain(String keyType)
    {
        return keyManager.getCertificateChain(keyType);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
        return keyManager.getClientAliases(keyType, issuers);
    }

    @Override
    public PrivateKey getPrivateKey(String keyType)
    {
        return keyManager.getPrivateKey(keyType);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        return keyManager.getServerAliases(keyType, issuers);
    }

    private String printObjects(Object[] objects)
    {
        if (objects == null)
            return "";
        
        StringBuilder sb = new StringBuilder();
        
        for (int i = 0; i < objects.length; i++)
        {
            Object object = objects[i];
            sb.append("\t").append(i + 1).append(". ").append(object.toString());
            
            if (i < objects.length - 1)
                sb.append("\r\n");
        }
        
        return sb.toString();
    }
    
    private int count(Object[] array)
    {
        return array != null ? array.length : 0;
    }

}
