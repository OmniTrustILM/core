package com.otilm.core.service.impl;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.model.crypto.KeyImportTerms;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ImportIdempotencyKeyTest {

    private static final byte[] FILE = {1, 2, 3, 4};
    private static final UUID PROFILE = UUID.randomUUID();
    private static final NameAndUuidDto REQUESTER = new NameAndUuidDto(UUID.randomUUID().toString(), "requester");

    @Test
    void of_isTheSameForTheSameImport() {
        // when
        String first = ImportIdempotencyKey.of(terms(PROFILE, REQUESTER, "fingerprint", false, List.of()), FILE);
        String second = ImportIdempotencyKey
                .of(terms(PROFILE, REQUESTER, "fingerprint", false, List.of()), FILE.clone());

        // then
        assertThat(first).isEqualTo(second).hasSize(64).matches("[0-9a-f]{64}");
    }

    @Test
    void of_differsWithEachTermOfTheImport() {
        // given
        String base = ImportIdempotencyKey.of(terms(PROFILE, REQUESTER, "fingerprint", false, List.of()), FILE);
        NameAndUuidDto otherRequester = new NameAndUuidDto(UUID.randomUUID().toString(), "requester");

        // when
        // then
        assertThat(List
                .of(ImportIdempotencyKey.of(terms(PROFILE, otherRequester, "fingerprint", false, List.of()), FILE),
                        ImportIdempotencyKey
                                .of(terms(UUID.randomUUID(), REQUESTER, "fingerprint", false, List.of()), FILE),
                        ImportIdempotencyKey
                                .of(terms(PROFILE, REQUESTER, "fingerprint", false, List.of()), new byte[]{1, 2, 3}),
                        ImportIdempotencyKey.of(terms(PROFILE, REQUESTER, "other", false, List.of()), FILE),
                        ImportIdempotencyKey.of(terms(PROFILE, REQUESTER, "fingerprint", true, List.of()), FILE),
                        ImportIdempotencyKey
                                .of(terms(PROFILE, REQUESTER, "fingerprint", false, List.of(attribute("a", "1"))),
                                        FILE)))
                .doesNotContain(base)
                .doesNotHaveDuplicates();
    }

    @Test
    void of_readsTheAttributesWhateverTheirOrder() {
        // when
        String oneOrder = ImportIdempotencyKey
                .of(terms(PROFILE, REQUESTER, "fingerprint", false, List.of(attribute("a", "1"), attribute("b", "2"))),
                        FILE);
        String otherOrder = ImportIdempotencyKey
                .of(terms(PROFILE, REQUESTER, "fingerprint", false, List.of(attribute("b", "2"), attribute("a", "1"))),
                        FILE);

        // then
        assertThat(oneOrder).isEqualTo(otherOrder);
    }

    @Test
    void of_readsTheAttributeContent() {
        // when
        String one = ImportIdempotencyKey
                .of(terms(PROFILE, REQUESTER, "fingerprint", false, List.of(attribute("a", "1"))), FILE);
        String other = ImportIdempotencyKey
                .of(terms(PROFILE, REQUESTER, "fingerprint", false, List.of(attribute("a", "2"))), FILE);

        // then
        assertThat(one).isNotEqualTo(other);
    }

    private static KeyImportTerms terms(UUID profileUuid, NameAndUuidDto requester, String fingerprint,
            boolean exportable, List<RequestAttribute> attributes) {
        TokenProfileFullModel profile = mock(TokenProfileFullModel.class);
        when(profile.uuid()).thenReturn(profileUuid);
        return new KeyImportTerms(profile, KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA, fingerprint, exportable,
                attributes, requester);
    }

    private static RequestAttribute attribute(String name, String value) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setUuid(UUID.nameUUIDFromBytes(name.getBytes()));
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV2(value)));
        return attribute;
    }
}
