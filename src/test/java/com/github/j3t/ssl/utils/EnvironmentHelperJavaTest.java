package com.github.j3t.ssl.utils;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;

import org.junit.Before;
import org.junit.Test;

public class EnvironmentHelperJavaTest
{
    private Field field;

    @Before
    public void setUp() throws Exception
    {
        field = EnvironmentHelper.class.getDeclaredField("JAVA_VERSION");
        field.setAccessible(true);
    }
    
    @Test
    public void testIsJava6() throws Exception
    {
        field.setDouble(EnvironmentHelper.class, 1.6d);
        assertTrue(EnvironmentHelper.isJava6());
        
        field.setDouble(EnvironmentHelper.class, 1.5d);
        assertFalse(EnvironmentHelper.isJava6());
    }
    
    @Test
    public void testIsJava6OrHigher() throws Exception
    {
        field.setDouble(EnvironmentHelper.class, 1.6d);
        assertTrue(EnvironmentHelper.isJava6OrHigher());
        
        field.setDouble(EnvironmentHelper.class, 1.5d);
        assertFalse(EnvironmentHelper.isJava6OrHigher());
    }

    @Test
    public void testIsJava7() throws Exception
    {
        field.setDouble(EnvironmentHelper.class, 1.7d);
        assertTrue(EnvironmentHelper.isJava7());
        
        field.setDouble(EnvironmentHelper.class, 1.5d);
        assertFalse(EnvironmentHelper.isJava7());
    }
    
    @Test
    public void testIsJava7OrHigher() throws Exception
    {
        field.setDouble(EnvironmentHelper.class, 1.7d);
        assertTrue(EnvironmentHelper.isJava7OrHigher());
        
        field.setDouble(EnvironmentHelper.class, 1.5d);
        assertFalse(EnvironmentHelper.isJava7OrHigher());
    }
    
    @Test
    public void testIsJava8() throws Exception
    {
        field.setDouble(EnvironmentHelper.class, 1.8d);
        assertTrue(EnvironmentHelper.isJava8());
        
        field.setDouble(EnvironmentHelper.class, 1.5d);
        assertFalse(EnvironmentHelper.isJava8());
    }
    
    @Test
    public void testIsJava8OrHigher() throws Exception
    {
        field.setDouble(EnvironmentHelper.class, 1.8d);
        assertTrue(EnvironmentHelper.isJava8OrHigher());
        
        field.setDouble(EnvironmentHelper.class, 1.5d);
        assertFalse(EnvironmentHelper.isJava8OrHigher());
    }
}
