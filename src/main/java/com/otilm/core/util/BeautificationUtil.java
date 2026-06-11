package com.otilm.core.util;

import org.apache.commons.lang3.StringUtils;

public class BeautificationUtil {
    public static String camelToHumanForm(String word) {
        return StringUtils.capitalize(
                StringUtils.join(
                        StringUtils.splitByCharacterTypeCamelCase(word),
                        ' '
                )
        );
    }
}
