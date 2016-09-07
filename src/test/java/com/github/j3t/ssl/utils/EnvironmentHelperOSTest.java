package com.github.j3t.ssl.utils;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;

import org.junit.Before;
import org.junit.Test;

public class EnvironmentHelperOSTest
{
    private Field field;

    @Before
    public void setUp() throws Exception
    {
        field = EnvironmentHelper.class.getDeclaredField("OS");
        field.setAccessible(true);
    }
    
    @Test
    public void testIsWindows() throws Exception
    {
        field.set(EnvironmentHelper.class, "win");
        assertTrue(EnvironmentHelper.isWindows());
        
        field.set(null, "dos");
        assertFalse(EnvironmentHelper.isWindows());
    }

    @Test
    public void testIsMac() throws Exception
    {
        field.set(EnvironmentHelper.class, "mac");
        assertTrue(EnvironmentHelper.isMac());
        
        field.set(null, "dos");
        assertFalse(EnvironmentHelper.isMac());
    }
    
    @Test
    public void testIsUnix() throws Exception
    {
        field.set(EnvironmentHelper.class, "nix");
        assertTrue(EnvironmentHelper.isUnix());
        
        field.set(EnvironmentHelper.class, "nux");
        assertTrue(EnvironmentHelper.isUnix());
        
        field.set(EnvironmentHelper.class, " aix");
        assertTrue(EnvironmentHelper.isUnix());
        
        field.set(null, "dos");
        assertFalse(EnvironmentHelper.isUnix());
    }
    
    @Test
    public void testIsSolaris() throws Exception
    {
        field.set(EnvironmentHelper.class, "sunos");
        assertTrue(EnvironmentHelper.isSolaris());
        
        field.set(null, "dos");
        assertFalse(EnvironmentHelper.isSolaris());
    }

}
