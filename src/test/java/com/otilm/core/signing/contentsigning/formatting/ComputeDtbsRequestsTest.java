package com.otilm.core.signing.contentsigning.formatting;

import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsRequestDto;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

class ComputeDtbsRequestsTest {

    /** The subtype fixes the discriminator, so picking the wrong one would send a family the profile never chose. */
    @ParameterizedTest
    @EnumSource(SignatureFamily.class)
    void requestForAFamilyCarriesThatFamily(SignatureFamily family) {
        // when
        ComputeDtbsRequestDto request = ComputeDtbsRequests.forFamily(family);

        // then
        assertThat(request.getFamily()).isEqualTo(family);
    }
}
