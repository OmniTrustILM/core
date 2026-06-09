package com.czertainly.core.util;

import com.otilm.api.model.core.audit.AuditLogDto;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.stream.Collectors;

public class UriParamsBuilderTest {

    private static final int DEFAULT_PAGE_SIZE = 10;
    private static final int MAX_PAGE_SIZE = 100;
    private static final int FIRST_PAGE = 0;

    @Test
    public void testBuildUri() throws UnsupportedEncodingException {
        AuditLogDto dto = new AuditLogDto();
        dto.setModule(Module.CORE);
        dto.setLoggedAt(OffsetDateTime.now());
        dto.setOperation(Operation.REQUEST);

        UriComponentsBuilder builder = createUriBuilder("https://localhost:8443/logs", dto);
        appendPageable(builder, PageRequest.of(1, 10, Sort.by(Sort.Order.desc("created"))));

        System.out.println(builder.toUriString());
    }

    private UriComponentsBuilder createUriBuilder(String resourcePath, Object searchParams) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromPath(resourcePath);
        // Use all non-null fields of the search parameters wrapper
        ReflectionUtils.doWithFields(searchParams.getClass(), new ReflectionUtils.FieldCallback() {
            @Override
            public void doWith(Field field) throws IllegalArgumentException, IllegalAccessException {
                Object value = FieldUtils.readField(searchParams, field.getName(), true);
                if (value != null) {
                    List<Object> values;
                    if (Collection.class.isAssignableFrom(field.getType())) {
                        values = ((Collection<?>) value).stream().collect(Collectors.toList());
                    } else {
                        values = Arrays.asList(value);
                    }
                    values.stream().forEach(v -> builder.queryParam(field.getName(), v));
                }
            }
        });
        // Return created URI builder
        return builder;
    }

    private void appendPageable(UriComponentsBuilder uriBuilder, Pageable pageable) {
        if (pageable == null) {
            appendPagingParams(uriBuilder, FIRST_PAGE, DEFAULT_PAGE_SIZE, null);
            return;
        }

        final Sort sort = pageable.getSort();
        final List<String> sortList = new ArrayList<>();
        if (sort != null) {
            sort.forEach(order -> sortList.add(asString(order)));
        }

        appendPagingParams(uriBuilder, pageable.getPageNumber(), pageable.getPageSize(), sortList);
    }

    private void appendPagingParams(UriComponentsBuilder uriBuilder, int pageNumber, int pageSize, List<String> sort) {
        if (pageNumber < FIRST_PAGE) {
            pageNumber = FIRST_PAGE;
        }

        if (pageSize <= 0) {
            pageSize = DEFAULT_PAGE_SIZE;
        } else if (pageSize > MAX_PAGE_SIZE) {
            pageSize = MAX_PAGE_SIZE;
        }

        uriBuilder.queryParam("page", pageNumber);
        uriBuilder.queryParam("size", pageSize);

        for (String item : Optional.ofNullable(sort).orElse(Collections.emptyList())) {
            uriBuilder.queryParam("sort", item);
        }
    }

    private String asString(final Sort.Order order) {
        Assertions.assertNotNull(order);
        Assertions.assertNotNull(order.getProperty());
        final Sort.Direction direction = Optional.ofNullable(order.getDirection()).orElse(Sort.Direction.ASC);
        return String.format("%s,%s", order.getProperty(), direction.name().toLowerCase());
    }
}
