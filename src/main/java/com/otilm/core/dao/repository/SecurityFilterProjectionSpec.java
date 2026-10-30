package com.otilm.core.dao.repository;

import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Selection;
import java.util.List;

public record SecurityFilterProjectionSpec<R>(Selection<? extends R> selection,
        List<Expression<?>> groupByExpressions) {
}
