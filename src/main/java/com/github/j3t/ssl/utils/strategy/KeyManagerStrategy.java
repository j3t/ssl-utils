
package com.github.j3t.ssl.utils.strategy;


/**
 * A strategy to select which alias is to select during the authentication, no matter the alias exists or the
 * certificate is valid. This can be used to override the standard authentication process.<br>
 * 
 * @see StrategyKeyManager
 * 
 * @author j3t
 * 
 */
public interface KeyManagerStrategy
{
    /**
     * Returns the selected alias.
     * 
     * @return {@link String} or <code>null</code> 
     */
    String chooseAlias();
}
