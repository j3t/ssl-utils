package com.github.j3t.ssl.utils;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Created by Jens Thielscher on 03.06.2017.
 */
public class StringHelperTest {
    @Test
    public void arrayToCommaSeparatedStringShouldReturnAnEmptyStringWhenArrayIsNull() throws Exception {
        assertEquals("", StringHelper.arrayToCommaSeparatedString(null));
    }

    @Test
    public void arrayToCommaSeparatedStringShouldReturnAnEmptyStringWhenArrayIsEmpty() throws Exception {
        assertEquals("", StringHelper.arrayToCommaSeparatedString(new Object[0]));
    }
}