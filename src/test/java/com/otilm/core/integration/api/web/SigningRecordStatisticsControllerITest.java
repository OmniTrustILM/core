package com.otilm.core.integration.api.web;

import com.otilm.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class SigningRecordStatisticsControllerITest extends BaseSpringBootTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void getSigningRecordStatistics_bindsPeriodCodeAndReturnsDto() throws Exception {
        mockMvc.perform(get("/v1/statistics/signingRecords").param("period", "7d"))
            .andExpectAll(status().isOk(),
                jsonPath("$.totalRetained").value(0),
                jsonPath("$.volumeOverTime").exists(),
                jsonPath("$.statByProfile").exists());
    }

    @Test
    void getSigningRecordStatistics_defaultsPeriodWhenOmitted() throws Exception {
        mockMvc.perform(get("/v1/statistics/signingRecords"))
            .andExpectAll(status().isOk(),
                jsonPath("$.volumeOverTime").exists());
    }

    @Test
    void getSigningRecordStatistics_rejectsUnknownPeriodCode() throws Exception {
        mockMvc.perform(get("/v1/statistics/signingRecords").param("period", "12h"))
            .andExpect(status().is4xxClientError());
    }
}
