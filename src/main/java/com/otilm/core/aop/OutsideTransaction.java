package com.otilm.core.aop;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Runs a method that waits on an external system with no transaction and without the request's open-in-view
 * EntityManager, so each short transaction inside releases its connection when it commits. A caller's transaction is
 * only suspended and keeps its connection.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
public @interface OutsideTransaction {
}
