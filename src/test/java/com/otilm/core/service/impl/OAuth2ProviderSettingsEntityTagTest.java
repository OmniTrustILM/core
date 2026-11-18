package com.otilm.core.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.otilm.api.model.core.settings.authentication.OAuth2ProviderSettingsDto;
import com.otilm.core.serialization.ObjectMapperFactory;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OAuth2ProviderSettingsEntityTagTest {

    private static final String STORED = "{\"name\":\"p\",\"issuerUrl\":\"https://issuer\",\"clientSecret\":\"s1\"}";

    // ── TagComputation ─────────────────────────────────────────────────────────

    @Nested
    class TagComputation {

        @Test
        void returnsSameTag_whenValueIsUnchanged() throws Exception {
            // given
            var value = STORED;

            // when
            String first = OAuth2ProviderSettingsEntityTag.of(value);
            String second = OAuth2ProviderSettingsEntityTag.of(value);

            // then
            assertThat(first).isEqualTo(second);
        }

        @Test
        void returnsSameTag_whenOnlyTheClientSecretDiffers() throws Exception {
            // given
            var otherSecret = STORED.replace("s1", "s2");

            // when
            String original = OAuth2ProviderSettingsEntityTag.of(STORED);
            String withOtherSecret = OAuth2ProviderSettingsEntityTag.of(otherSecret);

            // then
            assertThat(withOtherSecret).isEqualTo(original);
        }

        @Test
        void returnsSameTag_whenARowWithoutNewerFieldsIsRewrittenByAnUpdate() throws Exception {
            // given
            var storageMapper = ObjectMapperFactory.storage();
            var rewrittenByUpdate = storageMapper
                    .writeValueAsString(storageMapper.readValue(STORED, OAuth2ProviderSettingsDto.class));

            // when
            String original = OAuth2ProviderSettingsEntityTag.of(STORED);
            String rewritten = OAuth2ProviderSettingsEntityTag.of(rewrittenByUpdate);

            // then
            assertThat(rewrittenByUpdate).isNotEqualTo(STORED);
            assertThat(rewritten).isEqualTo(original);
        }

        @Test
        void returnsDifferentTag_whenAnotherFieldChanges() throws Exception {
            // given
            var otherIssuer = STORED.replace("https://issuer", "https://other");

            // when
            String original = OAuth2ProviderSettingsEntityTag.of(STORED);
            String changed = OAuth2ProviderSettingsEntityTag.of(otherIssuer);

            // then
            assertThat(changed).isNotEqualTo(original);
        }

        @Test
        void returnsQuotedBase64UrlSha256_whenTagIsComputed() throws Exception {
            // given
            var value = STORED;

            // when
            String tag = OAuth2ProviderSettingsEntityTag.of(value);

            // then
            assertThat(tag).matches("\"[A-Za-z0-9_-]{43}\"");
        }

        @Test
        void throwsJsonProcessing_whenValueIsNotJson() {
            // given
            var notJson = "{not json";

            // when
            ThrowingCallable compute = () -> OAuth2ProviderSettingsEntityTag.of(notJson);

            // then
            assertThatThrownBy(compute).isInstanceOf(JsonProcessingException.class);
        }
    }

    // ── Matching ───────────────────────────────────────────────────────────────

    @Nested
    class Matching {

        @ParameterizedTest
        @NullSource
        @ValueSource(strings = {"", "   "})
        void matches_whenThereIsNoPrecondition(String ifMatch) throws Exception {
            // given
            String current = OAuth2ProviderSettingsEntityTag.of(STORED);

            // when
            boolean matches = OAuth2ProviderSettingsEntityTag.matches(ifMatch, current);

            // then
            assertThat(matches).isTrue();
        }

        @Test
        void matches_whenTheTagIsTheCurrentOne() throws Exception {
            // given
            String current = OAuth2ProviderSettingsEntityTag.of(STORED);

            // when
            boolean matches = OAuth2ProviderSettingsEntityTag.matches(current, current);

            // then
            assertThat(matches).isTrue();
        }

        @Test
        void refuses_whenTheTagIsAnotherOne() throws Exception {
            // given
            String current = OAuth2ProviderSettingsEntityTag.of(STORED);
            var staleTag = "\"stale\"";

            // when
            boolean matches = OAuth2ProviderSettingsEntityTag.matches(staleTag, current);

            // then
            assertThat(matches).isFalse();
        }

        @Test
        void matches_whenTheHeaderIsAWildcard() throws Exception {
            // given
            String current = OAuth2ProviderSettingsEntityTag.of(STORED);

            // when
            boolean matches = OAuth2ProviderSettingsEntityTag.matches("*", current);

            // then
            assertThat(matches).isTrue();
        }

        @Test
        void refuses_whenTheTagIsWeak() throws Exception {
            // given
            String current = OAuth2ProviderSettingsEntityTag.of(STORED);
            var weakTag = "W/" + current;

            // when
            boolean matches = OAuth2ProviderSettingsEntityTag.matches(weakTag, current);

            // then
            assertThat(matches).isFalse();
        }

        @Test
        void matches_whenTheCurrentTagIsInAList() throws Exception {
            // given
            String current = OAuth2ProviderSettingsEntityTag.of(STORED);
            var list = "\"x\", " + current;

            // when
            boolean matches = OAuth2ProviderSettingsEntityTag.matches(list, current);

            // then
            assertThat(matches).isTrue();
        }
    }
}
