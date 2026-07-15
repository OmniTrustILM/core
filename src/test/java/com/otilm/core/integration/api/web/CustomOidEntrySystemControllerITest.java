package com.otilm.core.integration.api.web;

import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class CustomOidEntrySystemControllerITest extends BaseSpringBootTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void listSystemOidEntries_returnsAllWhenNoCategory() throws Exception {
        mockMvc.perform(get("/v1/oids/system"))
            .andExpectAll(status().isOk(),
                jsonPath("$.length()").value(SystemOid.values().length),
                jsonPath("$[?(@.oid == '" + SystemOid.COMMON_NAME.getOid() + "')].additionalProperties.code").value(SystemOid.COMMON_NAME.getCode()));
    }

    @Test
    void listSystemOidEntries_bindsCategoryCodeAndFilters() throws Exception {
        long expectedRdnCount = Arrays.stream(SystemOid.values())
            .filter(o -> o.getCategory() == OidCategory.RDN_ATTRIBUTE_TYPE).count();
        mockMvc.perform(get("/v1/oids/system").param("category", OidCategory.RDN_ATTRIBUTE_TYPE.getCode()))
            .andExpectAll(status().isOk(),
                jsonPath("$.length()").value((int) expectedRdnCount));
    }

    @Test
    void listSystemOidEntries_rejectsUnknownCategoryCode() throws Exception {
        mockMvc.perform(get("/v1/oids/system").param("category", "notACategory"))
            .andExpect(status().is4xxClientError());
    }
}
