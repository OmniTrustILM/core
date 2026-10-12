package com.otilm.core.api.web;

import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.util.ApplicationMessageConverters;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CryptographicKeyControllerRemoveFromInventoryTest {

    private final CryptographicKeyExternalService keyService = mock(CryptographicKeyExternalService.class);
    private final CryptographicKeyControllerImpl controller = new CryptographicKeyControllerImpl();
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        controller.setCryptographicKeyExternalService(keyService);
        mvc = MockMvcBuilders
                .standaloneSetup(controller)
                .setMessageConverters(ApplicationMessageConverters.get())
                .build();
    }

    @Test
    void removeKeysFromInventory_answersOkWithTheKeysNotRemoved() throws Exception {
        // given
        String removable = UUID.randomUUID().toString();
        String compromised = UUID.randomUUID().toString();
        String reason = "It is compromised and would come back active when onboarded again. Destroy it instead.";
        when(keyService.removeKeysFromInventory(List.of(removable, compromised)))
                .thenReturn(List.of(BulkActionMessageDto.failureWithMessage(compromised, "compromised key", reason)));

        // when
        ResultActions response = mvc
                .perform(patch("/v1/keys/removeFromInventory")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("[\"%s\",\"%s\"]".formatted(removable, compromised)));

        // then
        response
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].uuid").value(compromised))
                .andExpect(jsonPath("$[0].name").value("compromised key"))
                .andExpect(jsonPath("$[0].message").value(reason));
    }
}
