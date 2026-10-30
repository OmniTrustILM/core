package com.otilm.core.service.handler;

/**
 * One connector result item, decoded to base64. {@code data} is null for verification results and {@code result} is
 * null for cipher and signature results.
 */
public record OperationResultItem(String data, Boolean result, String identifier, Object details) {
}
