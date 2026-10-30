package com.otilm.core.service.model;

public class SecuredItem<T> {
    private final boolean doesUserHaveAccess;
    private final T item;

    public SecuredItem(T item, boolean doesUserHaveAccess) {
        this.item = item;
        this.doesUserHaveAccess = doesUserHaveAccess;
    }

    T get() {
        return item;
    }

    boolean doesUserHaveAccess() {
        return this.doesUserHaveAccess;
    }
}
