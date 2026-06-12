package com.otilm.core.config;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import java.io.IOException;

@Component
public class ScepHttpMessageConverter<T> extends AbstractHttpMessageConverter<byte[]> {

    public ScepHttpMessageConverter() {
        super(new MediaType("application", "x-x509-ca-cert"),
                new MediaType("application", "x-x509-ca-ra-cert"),
                new MediaType("application", "x-pki-message"),
                MediaType.ALL);
    }

    public boolean supports(Class<?> clazz) {
        return byte[].class == clazz;
    }

    public byte[] readInternal(Class<? extends byte[]> clazz, HttpInputMessage inputMessage) throws IOException {
        return inputMessage.getBody().readAllBytes();
    }

    protected Long getContentLength(byte[] bytes, @Nullable MediaType contentType) {
        return (long)bytes.length;
    }

    protected void writeInternal(byte[] bytes, HttpOutputMessage outputMessage) throws IOException {
        StreamUtils.copy(bytes, outputMessage.getBody());
    }
}
