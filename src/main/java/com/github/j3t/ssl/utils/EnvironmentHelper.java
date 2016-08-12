
package com.github.j3t.ssl.utils;


/**
 * Helper to identify the environment.
 *
 * @author j3t
 */
public class EnvironmentHelper
{
    private static String OS = createOperatingSystem();
    private static double JAVA_VERSION = createJavaVersion();

    public static boolean isWindows()
    {
        return (OS.indexOf("win") >= 0);
    }

    public static boolean isMac()
    {
        return (OS.indexOf("mac") >= 0);
    }

    public static boolean isUnix()
    {
        return (OS.indexOf("nix") >= 0 || OS.indexOf("nux") >= 0 || OS.indexOf("aix") > 0);
    }

    public static boolean isSolaris()
    {
        return (OS.indexOf("sunos") >= 0);
    }

    public static boolean isJava6()
    {
        return JAVA_VERSION == 1.6d;
    }
    
    public static boolean isJava6OrHigher()
    {
        return JAVA_VERSION >= 1.6d;
    }
    
    public static boolean isJava7()
    {
        return JAVA_VERSION == 1.7d;
    }
    
    public static boolean isJava7OrHigher()
    {
        return JAVA_VERSION >= 1.7d;
    }
    
    public static boolean isJava8()
    {
        return JAVA_VERSION == 1.8d;
    }

    public static boolean isJava8OrHigher()
    {
        return JAVA_VERSION >= 1.8d;
    }

    private static String createOperatingSystem()
    {
        String os = System.getProperty("os.name");
        
        if (os != null)
            return os.toLowerCase();
        
        return "";
    }

    private static double createJavaVersion()
    {
        try
        {
            return Double.parseDouble(System.getProperty("java.specification.version"));
        }
        catch (NumberFormatException e)
        {
            return 0d;
        }
    }
}
