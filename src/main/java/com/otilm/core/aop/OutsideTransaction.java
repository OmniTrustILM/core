package com.otilm.core.aop;

import jakarta.transaction.Transactional;
import jakarta.transaction.Transactional.TxType;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Runs a method that waits on an external system with no transaction and, when no transaction scope is active yet,
 * without the request's open-in-view EntityManager, so each short transaction inside runs on an EntityManager of its
 * own and flushes nothing the request has read. Inside an active scope the scope's EntityManager stays bound. A
 * caller's transaction is only suspended and keeps its connection.
 * <p>
 * Spring applies Jakarta's {@code @Transactional} as it does its own. Rollback rules mean nothing without a
 * transaction, and Jakarta's form does not ask every method that throws a checked exception to declare them.
 * </p>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Transactional(TxType.NOT_SUPPORTED)
public @interface OutsideTransaction {
}
