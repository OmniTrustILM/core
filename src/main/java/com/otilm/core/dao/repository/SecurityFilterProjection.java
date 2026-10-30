package com.otilm.core.dao.repository;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Root;

@FunctionalInterface
public interface SecurityFilterProjection<T, R> {

    SecurityFilterProjectionSpec<R> create(Root<T> root, CriteriaBuilder builder);
}
