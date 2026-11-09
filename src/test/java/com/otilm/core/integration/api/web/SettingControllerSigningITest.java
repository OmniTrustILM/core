package com.otilm.core.integration.api.web;

import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class SettingControllerSigningITest extends BaseSpringBootTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void answersTheDefaultSigningLimit_whenNoneIsStored() throws Exception {
        // given — no signing row is stored

        // when
        var read = mockMvc.perform(get("/v1/settings/platform"));

        // then
        read.andExpectAll(status().isOk(), jsonPath("$.signing.maxItemsPerRequest").value(100));
    }

    /** The administrator UI splits this entry at the field path and shows the message on the field. */
    @Test
    void rejectsWithTheFieldPath_whenTheSigningLimitExceedsTheCeiling() throws Exception {
        // given
        var aboveCeiling = "{\"signing\":{\"maxItemsPerRequest\":1001}}";

        // when
        var update = mockMvc
                .perform(put("/v1/settings/platform").contentType(MediaType.APPLICATION_JSON).content(aboveCeiling));

        // then
        update
                .andExpectAll(status().isUnprocessableContent(),
                        jsonPath("$[0]").value("signing.maxItemsPerRequest must not exceed 1000"));
    }
}
