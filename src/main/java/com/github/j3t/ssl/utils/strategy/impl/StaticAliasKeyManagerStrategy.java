package com.github.j3t.ssl.utils.strategy.impl;

import com.github.j3t.ssl.utils.strategy.KeyManagerStrategy;

/**
 * Implementation of the {@link KeyManagerStrategy} that will choose always the same alias.
 *
 * @author j3t
 */
public class StaticAliasKeyManagerStrategy implements KeyManagerStrategy
{

    private String alias;

    /**
     * Creates an instance of {@link StaticAliasKeyManagerStrategy}.
     * 
     * @param alias the alias be returned when {@link #chooseAlias()} is called
     */
    public StaticAliasKeyManagerStrategy(String alias)
    {
        this.alias = alias;
    }

    @Override
    public String chooseAlias()
    {
        return alias;
    }

}
