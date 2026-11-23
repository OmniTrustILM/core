package com.otilm.core.service.impl;

import com.otilm.api.exception.ValidationException;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SettingServiceImplApplicationResourceTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "https://ilm.example.com/api",
            "http://localhost:8080/api?tenant=a",
            "https://ilm.example.com",
            "https://10.0.0.1/api",
            "https://[2001:db8::1]/api",
            "https://ilm.example.com/a%20b",
            "HTTPS://ILM.example.com/api",
            "https://ilm.example.com/api?x=1&y=%2F",
            "https://xn--ilm-9na.example/api",
            "https://ilm.example.com:99999/api"})
    void acceptsResource_whenItIsAConformingHttpUri(String resource) {
        // given
        var conformingResource = resource;

        // when
        ThrowingCallable validation = () -> SettingServiceImpl.validateApplicationResource(conformingResource);

        // then
        assertThatCode(validation).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "ilm.example.com/api",
            "ftp://ilm.example.com/api",
            "https://ilm.example.com/api#part",
            "https://ilm.example.com/api#",
            "https://user:secret@ilm.example.com/api",
            "https://user@ilm.example.com/api",
            "https://@ilm.example.com/api",
            "https://ilm.example.com/a b",
            "https://ilm.example.com/a%zz",
            "https://exa_mple.com/api",
            "https:///api",
            "https://[bad",
            "https://ilm.example.com/a|b",
            "https://-ilm.example.com/api"})
    void refusesResource_whenItIsNotAConformingHttpUri(String resource) {
        // given
        var nonConformingResource = resource;

        // when
        ThrowingCallable validation = () -> SettingServiceImpl.validateApplicationResource(nonConformingResource);

        // then
        assertThatThrownBy(validation).isInstanceOf(ValidationException.class);
    }

    @ParameterizedTest
    @NullSource
    void acceptsResource_whenItIsUnset(String resource) {
        // given
        var unsetResource = resource;

        // when
        ThrowingCallable validation = () -> SettingServiceImpl.validateApplicationResource(unsetResource);

        // then
        assertThatCode(validation).doesNotThrowAnyException();
    }
}
