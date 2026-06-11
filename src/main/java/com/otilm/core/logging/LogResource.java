package com.otilm.core.logging;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface LogResource {
    boolean uuid() default false;
    boolean name() default false;
    boolean resource() default false;
    boolean affiliated() default false;
}
