package com.otilm.core.signing.contentsigning.profile;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.common.signature.SignatureFamily;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SignatureFamilyInterfacesTest {

    @Test
    void mapsEachFamilyToItsOwnFormattingInterface() {
        // given / when / then
        assertThat(SignatureFamilyInterfaces.of(SignatureFamily.PADES)).isEqualTo(ConnectorInterface.PADES_FORMATTING);
        assertThat(SignatureFamilyInterfaces.of(SignatureFamily.XADES)).isEqualTo(ConnectorInterface.XADES_FORMATTING);
        assertThat(SignatureFamilyInterfaces.of(SignatureFamily.CADES)).isEqualTo(ConnectorInterface.CADES_FORMATTING);
        assertThat(SignatureFamilyInterfaces.of(SignatureFamily.JADES)).isEqualTo(ConnectorInterface.JADES_FORMATTING);
    }
}
