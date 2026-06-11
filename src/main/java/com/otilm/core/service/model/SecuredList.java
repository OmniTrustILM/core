package com.otilm.core.service.model;

import com.otilm.core.security.authz.SecurityFilter;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class SecuredList<T extends Securable> {

    private final List<T> allowed;

    private final List<T> forbidden;

    private final List<T> all;

    public static <T extends Securable> SecuredList<T> fromFilter(SecurityFilter filter, List<T> items) {
        List<SecuredItem<T>> securedItems = items.stream()
                .map(item -> {
                    if (filter.getResourceFilter().areOnlySpecificObjectsAllowed()) {
                        boolean isAccessibleByUser = filter.getResourceFilter().getAllowedObjects().contains(item.getUuid());
                        return new SecuredItem<>(item, isAccessibleByUser);
                    } else {
                        boolean isForbiddenToUser = filter.getResourceFilter().getForbiddenObjects().contains(item.getUuid());
                        return new SecuredItem<>(item, !isForbiddenToUser);
                    }
                })
                .collect(Collectors.toList());

        return new SecuredList<>(securedItems);
    }

    public SecuredList(List<SecuredItem<T>> items) {
        allowed = new ArrayList<>();
        forbidden = new ArrayList<>();
        all = new ArrayList<>();

        addAll(items);
    }

    public int size() {
        return all.size();
    }

    public boolean isEmpty() {
        return all.isEmpty();
    }

    public boolean isNotEmpty() {
        return !isEmpty();
    }

    public void add(SecuredItem<T> securedItem) {
        if (securedItem.doesUserHaveAccess()) {
            allowed.add(securedItem.get());
        } else {
            forbidden.add(securedItem.get());
        }

        all.add(securedItem.get());
    }

    public void addAll(List<? extends SecuredItem<T>> items) {
        for (SecuredItem<T> item : items) {
            this.add(item);
        }
    }

    public List<T> getAllowed() {
        return allowed;
    }

    public List<T> getForbidden() {
        return forbidden;
    }

    public List<T> getAll() {
        return all;
    }
}
