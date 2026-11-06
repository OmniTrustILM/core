package com.otilm.core.integration.api.web;

import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureParameterGroup;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.hamcrest.Matchers.hasItem;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class SignatureParameterControllerITest extends BaseSpringBootTest {

    private static final String GROUPS_ENDPOINT = "/v1/signatureParameters/groups";

    private static final String PADES_PLACEMENT_FIELDS = "$[?(@.family == '" + SignatureFamily.Codes.PADES + "')]"
            + ".groups[?(@.group == '" + SignatureParameterGroup.Codes.VISIBLE_SIGNATURE_PLACEMENT + "')].fields[*]";

    @Autowired
    private MockMvc mockMvc;

    @Test
    void listsThePageFieldUnderThePadesPlacementGroup() throws Exception {
        // given
        var placementPage = "visibleSignature.placement.page";

        // when
        ResultActions response = mockMvc.perform(get(GROUPS_ENDPOINT));

        // then
        response.andExpectAll(status().isOk(), jsonPath(PADES_PLACEMENT_FIELDS, hasItem(placementPage)));
    }

    @Test
    void returnsTheGroups_whenOpaDeniesEveryCheck() throws Exception {
        // given
        var opaDenial = new AccessDeniedException("OPA denies every check");
        when(opaClient.checkResourceAccess(any(), any(), any(), any())).thenThrow(opaDenial);
        when(opaClient.checkObjectAccess(any(), any(), any(), any())).thenThrow(opaDenial);

        // when
        ResultActions response = mockMvc.perform(get(GROUPS_ENDPOINT));

        // then
        response.andExpect(status().isOk());
    }
}
