package com.otilm.core.integration.api.web;

import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureParameterGroup;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.test.web.servlet.assertj.MvcTestResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@AutoConfigureMockMvc
class SignatureParameterControllerITest extends BaseSpringBootTest {

    private static final String GROUPS_ENDPOINT = "/v1/signatureParameters/groups";

    private static final String PADES_PLACEMENT_FIELDS = "$[?(@.family == '" + SignatureFamily.Codes.PADES + "')]"
            + ".groups[?(@.group == '" + SignatureParameterGroup.Codes.VISIBLE_SIGNATURE_PLACEMENT + "')].fields[*]";

    @Autowired
    private MockMvcTester mvc;

    @Test
    void listsThePageFieldUnderThePlacementGroup_whenFamilyIsPades() {
        // given
        var placementPage = "visibleSignature.placement.page";

        // when
        MvcTestResult response = mvc.get().uri(GROUPS_ENDPOINT).exchange();

        // then
        assertThat(response)
                .hasStatusOk()
                .bodyJson()
                .extractingPath(PADES_PLACEMENT_FIELDS)
                .asArray()
                .contains(placementPage);
    }

    @Test
    void returnsTheGroups_whenOpaDeniesEveryCheck() {
        // given
        var opaDenial = new AccessDeniedException("OPA denies every check");
        when(opaClient.checkResourceAccess(any(), any(), any(), any())).thenThrow(opaDenial);
        when(opaClient.checkObjectAccess(any(), any(), any(), any())).thenThrow(opaDenial);

        // when
        MvcTestResult response = mvc.get().uri(GROUPS_ENDPOINT).exchange();

        // then
        assertThat(response).hasStatusOk();
    }
}
