package com.github.j3t.ssl.utils;

import static org.junit.Assert.*;
import static org.junit.Assume.*;

import org.junit.Test;

public class EnvironmentHelperIT
{
    @Test
    public void givenWindows()
    {
        assumeTrue("Operating System isn't Windows!", System.getProperty("os.name").toLowerCase().contains("windows"));

        assertTrue(EnvironmentHelper.isWindows());
        assertFalse(EnvironmentHelper.isUnix());
        assertFalse(EnvironmentHelper.isMac());
        assertFalse(EnvironmentHelper.isSolaris());
    }

    @Test
    public void givenOSX()
    {
        assumeTrue("Operating System isn't OSX!", System.getProperty("os.name").toLowerCase().contains("mac"));

        assertFalse(EnvironmentHelper.isWindows());
        assertFalse(EnvironmentHelper.isUnix());
        assertTrue(EnvironmentHelper.isMac());
        assertFalse(EnvironmentHelper.isSolaris());
    }
    
    @Test
    public void givenUnix()
    {
        assumeTrue("Operating System isn't Unix!", System.getProperty("os.name").toLowerCase().contains("unix"));

        assertFalse(EnvironmentHelper.isWindows());
        assertTrue(EnvironmentHelper.isUnix());
        assertFalse(EnvironmentHelper.isMac());
        assertFalse(EnvironmentHelper.isSolaris());
    }
    
    @Test
    public void givenLinux()
    {
        assumeTrue("Operating System isn't Linux!", System.getProperty("os.name").toLowerCase().contains("linux"));

        assertFalse(EnvironmentHelper.isWindows());
        assertTrue(EnvironmentHelper.isUnix());
        assertFalse(EnvironmentHelper.isMac());
        assertFalse(EnvironmentHelper.isSolaris());
    }
    
    @Test
    public void givenAIX()
    {
        assumeTrue("Operating System isn't AIX!", System.getProperty("os.name").toLowerCase().contains("aix"));

        assertFalse(EnvironmentHelper.isWindows());
        assertTrue(EnvironmentHelper.isUnix());
        assertFalse(EnvironmentHelper.isMac());
        assertFalse(EnvironmentHelper.isSolaris());
    }
    
    @Test
    public void givenSolaris()
    {
        assumeTrue("Operating System isn't Solaris!", System.getProperty("os.name").toLowerCase().contains("solaris"));

        assertFalse(EnvironmentHelper.isWindows());
        assertFalse(EnvironmentHelper.isUnix());
        assertFalse(EnvironmentHelper.isMac());
        assertTrue(EnvironmentHelper.isSolaris());
    }

    @Test
    public void givenJava6()
    {
        assumeTrue("Java Version isn't 6!", System.getProperty("java.version").startsWith("1.6"));
        
        assertTrue(EnvironmentHelper.isJava6());
        assertTrue(EnvironmentHelper.isJava6OrHigher());
        assertFalse(EnvironmentHelper.isJava7());
        assertFalse(EnvironmentHelper.isJava7OrHigher());
        assertFalse(EnvironmentHelper.isJava8());
        assertFalse(EnvironmentHelper.isJava8OrHigher());
    }

    @Test
    public void givenJava7()
    {
        assumeTrue("Java Version isn't 7!", System.getProperty("java.version").startsWith("1.7"));
        
        assertFalse(EnvironmentHelper.isJava6());
        assertTrue(EnvironmentHelper.isJava6OrHigher());
        assertTrue(EnvironmentHelper.isJava7());
        assertTrue(EnvironmentHelper.isJava7OrHigher());
        assertFalse(EnvironmentHelper.isJava8());
        assertFalse(EnvironmentHelper.isJava8OrHigher());
    }
    
    @Test
    public void givenJava8()
    {
        assumeTrue("Java Version isn't 7!", System.getProperty("java.version").startsWith("1.8"));
        
        assertFalse(EnvironmentHelper.isJava6());
        assertTrue(EnvironmentHelper.isJava6OrHigher());
        assertFalse(EnvironmentHelper.isJava7());
        assertTrue(EnvironmentHelper.isJava7OrHigher());
        assertTrue(EnvironmentHelper.isJava8());
        assertTrue(EnvironmentHelper.isJava8OrHigher());
    }
    
}
