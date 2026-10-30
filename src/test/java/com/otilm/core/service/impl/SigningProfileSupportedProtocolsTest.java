package com.otilm.core.service.impl;

import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.core.signing.SigningProtocol;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the protocol list an operator may enable on a Signing Profile. Some {@link SigningProtocol} values record an
 * invocation the platform makes on its own and have no client edge to authenticate, so offering one as enableable would
 * advertise a route no caller can take.
 */
class SigningProfileSupportedProtocolsTest {

    private final SigningProfileServiceImpl service = new SigningProfileServiceImpl();

    @Test
    void offersOnlyProtocolsAnOperatorCanEnable() {
        // when
        var offered = Arrays
                .stream(SigningWorkflowType.values())
                .flatMap(workflowType -> service.listSupportedProtocols(workflowType).stream())
                .toList();

        // then
        assertThat(offered)
                .isNotEmpty()
                .allMatch(SigningProtocol::isEnableableOnProfile)
                .doesNotContain(SigningProtocol.INTERNAL_TSA);
    }

    @ParameterizedTest
    @EnumSource(value = SigningWorkflowType.class, names = "TIMESTAMPING")
    void offersTheTimestampingProtocolForTimestampingProfiles(SigningWorkflowType workflowType) {
        // when / then
        assertThat(service.listSupportedProtocols(workflowType)).containsExactly(SigningProtocol.TSP);
    }
}
