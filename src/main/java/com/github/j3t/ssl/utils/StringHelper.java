package com.github.j3t.ssl.utils;

/**
 * Helper class to handle/create {@link String} objects.
 *
 * @author j3t
 */
public class StringHelper {

    /**
     * Returns the given array as a comma separated {@link String}. All elements will be converted to a String and
     * joined by a comma.
     *
     * @param array the given array
     * @return elements as a comma separted {@link String} or an empty {@link String}
     */
    public static String arrayToCommaSeparatedString(Object[] array) {
        StringBuilder sb = new StringBuilder();

        if (array != null)
            for (Object o : array) {
                if (sb.length() > 0)
                    sb.append(", ");
                sb.append(o.toString());
            }

        return sb.toString();
    }
}
