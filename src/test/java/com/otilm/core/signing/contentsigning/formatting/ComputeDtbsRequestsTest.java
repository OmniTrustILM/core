package com.otilm.core.signing.contentsigning.formatting;

import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsRequestDto;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

class ComputeDtbsRequestsTest {

    @ParameterizedTest
    @EnumSource(SignatureFamily.class)
    void requestForAFamilyCarriesThatFamily(SignatureFamily family) {
        // when
        ComputeDtbsRequestDto request = ComputeDtbsRequests.forFamily(family);

        // then
        assertThat(request.getFamily()).isEqualTo(family);
    }
}
