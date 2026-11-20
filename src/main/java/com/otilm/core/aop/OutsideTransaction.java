package com.otilm.core.aop;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Runs a method that waits on an external system with no transaction and, when no transaction scope is active yet,
 * without the request's open-in-view EntityManager, so each short transaction inside runs on an EntityManager of its
 * own and flushes nothing the request has read. Inside an active scope the scope's EntityManager stays bound. A
 * caller's transaction is only suspended and keeps its connection.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
public @interface OutsideTransaction {
}
