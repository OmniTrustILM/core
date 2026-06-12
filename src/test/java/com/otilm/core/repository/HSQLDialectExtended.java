package com.otilm.core.repository;

import org.hibernate.dialect.HSQLDialect;

public class HSQLDialectExtended extends HSQLDialect {

    @Override
    public String toBooleanValueString(boolean bool) {
        return bool ? "TRUE" : "FALSE";
    }

}
