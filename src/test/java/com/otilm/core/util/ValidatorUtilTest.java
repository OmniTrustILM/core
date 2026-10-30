package com.otilm.core.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ValidatorUtilTest {

    @Test
    public void testContainUnreservedCharacters() {
        Assertions.assertTrue(ValidatorUtil.containsUnreservedCharacters("blabla**"));
        Assertions.assertTrue(ValidatorUtil.containsUnreservedCharacters("bla bla"));
    }

    @Test
    public void testNotContainUnreservedCharacters() {
        Assertions.assertFalse(ValidatorUtil.containsUnreservedCharacters("blabla"));
    }

}
