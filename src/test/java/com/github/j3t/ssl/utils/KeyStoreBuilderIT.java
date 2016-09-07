package com.github.j3t.ssl.utils;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

import org.junit.Test;

public class KeyStoreBuilderIT
{
    @Test
    public void givenWindowsOS_whenCreateWindowsMy_thenKeyStoreShouldNotNull() throws Exception
    {
        assumeTrue("Operating System isn't Windows!", EnvironmentHelper.isWindows());
        
        assertNotNull(KeyStoreBuilder.createWindowsMy());
    }

    @Test
    public void givenWindowsOS_whenCreateWindowsMyFixed_thenKeyStoreShouldNotNull() throws Exception
    {
        assumeTrue("Operating System isn't Windows!", EnvironmentHelper.isWindows());
        assumeTrue("Java Version isn't 6 or 7!", EnvironmentHelper.isJava6OrHigher() && !EnvironmentHelper.isJava8OrHigher());
        
        assertNotNull(KeyStoreBuilder.createWindowsMyFixed());
    }
    
    @Test
    public void givenWindowsOS_whenCreateWindowsRoot_thenKeyStoreShouldNotNull() throws Exception
    {
        assumeTrue("Operating System isn't Windows!", EnvironmentHelper.isWindows());
        
        assertNotNull(KeyStoreBuilder.createWindowsRoot());
    }
}
