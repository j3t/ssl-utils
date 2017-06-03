package com.github.j3t.ssl.utils;

import com.github.j3t.ssl.utils.types.SslProtocol;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

@RunWith(Parameterized.class)
public class SSLContextBuilderProtocolTest {
    private boolean test;
    private String expectedProtocol;

    public SSLContextBuilderProtocolTest(boolean test, String expectedProtocol) {
        this.test = test;
        this.expectedProtocol = expectedProtocol;
    }

    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {EnvironmentHelper.isJava6(), SslProtocol.TLSv10},
                {EnvironmentHelper.isJava7(), SslProtocol.TLSv12},
                {EnvironmentHelper.isJava7OrHigher(), SslProtocol.TLSv12},
                {EnvironmentHelper.isJava8(), SslProtocol.TLSv12},
                {EnvironmentHelper.isJava8OrHigher(), SslProtocol.TLSv12},
        });
    }

    @Test
    public void givenSSLContextWithDefaultProtocol_whenTestOk_thenGetProtocolShouldReturnExpectedProtocol() throws Exception {
        assumeTrue(test);
        assertEquals(expectedProtocol, SSLContextBuilder.create().build().getProtocol());
    }
}
