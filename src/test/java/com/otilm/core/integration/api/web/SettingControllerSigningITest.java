package com.otilm.core.integration.api.web;

import com.jayway.jsonpath.JsonPath;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

@AutoConfigureMockMvc
class SettingControllerSigningITest extends BaseSpringBootTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void answersTheDefaultSigningLimit_whenNoneIsStored() throws Exception {
        // given — no signing row is stored

        // when
        MvcResult read = mockMvc.perform(get("/v1/settings/platform")).andReturn();

        // then
        assertThat(read.getResponse().getStatus()).isEqualTo(200);
        String body = read.getResponse().getContentAsString();
        Integer maxItemsPerRequest = JsonPath.read(body, "$.signing.maxItemsPerRequest");
        assertThat(maxItemsPerRequest).isEqualTo(100);
    }

    /** The administrator UI splits this entry at the field path and shows the message on the field. */
    @Test
    void rejectsWithTheFieldPath_whenTheSigningLimitExceedsTheCeiling() throws Exception {
        // given
        var aboveCeiling = "{\"signing\":{\"maxItemsPerRequest\":1001}}";

        // when
        MvcResult update = mockMvc
                .perform(put("/v1/settings/platform").contentType(MediaType.APPLICATION_JSON).content(aboveCeiling))
                .andReturn();

        // then
        assertThat(update.getResponse().getStatus()).isEqualTo(422);
        String body = update.getResponse().getContentAsString();
        List<String> refusals = JsonPath.read(body, "$");
        assertThat(refusals).containsExactly("signing.maxItemsPerRequest must not exceed 1000");
    }
}
