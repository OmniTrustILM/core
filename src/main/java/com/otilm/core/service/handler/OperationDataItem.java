package com.otilm.core.service.handler;

/** One batch item as the Core API carries it: base64 payload plus the caller's identifier, which may be null. */
public record OperationDataItem(String data, String identifier) {
}
