package com.otilm.core.integration.api.web;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.Comment;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class CommentSortDirectionBindingITest extends BaseSpringBootTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CommentRepository commentRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    private String listUrl;

    @BeforeEach
    void createHostObjectWithComments() {
        RaProfile raProfile = new RaProfile();
        raProfile.setName("tst-ra-profile");
        UUID raProfileUuid = raProfileRepository.save(raProfile).getUuid();
        listUrl = "/v1/comments/%s/%s".formatted(Resource.RA_PROFILE.getCode(), raProfileUuid);

        // Explicit stamps, so a createdAt tie cannot leave the assertions resolving on the tie-break
        OffsetDateTime firstInstant = OffsetDateTime.parse("2026-09-01T10:00:00Z");
        save(raProfileUuid, "oldest", firstInstant);
        save(raProfileUuid, "newest", firstInstant.plusMinutes(1));
    }

    private void save(UUID objectUuid, String body, OffsetDateTime createdAt) {
        Comment comment = new Comment();
        comment.setResource(Resource.RA_PROFILE);
        comment.setObjectUuid(objectUuid);
        comment.setAuthorUuid(UUID.randomUUID());
        comment.setAuthorUsername("tst-user");
        comment.setBody(body);
        comment.setCreatedAt(createdAt);
        commentRepository.saveAndFlush(comment);
    }

    @Test
    void listComments_bindsTheLowercaseDirectionCodeAndOrdersNewestFirst() throws Exception {
        mockMvc
                .perform(get(listUrl).param("sortDirection", "desc"))
                .andExpectAll(status().isOk(), jsonPath("$.comments[0].body").value("newest"),
                        jsonPath("$.comments[1].body").value("oldest"));
    }

    @Test
    void listComments_defaultsToOldestFirstWhenTheDirectionIsOmitted() throws Exception {
        mockMvc.perform(get(listUrl)).andExpectAll(status().isOk(), jsonPath("$.comments[0].body").value("oldest"));
    }

    @Test
    void listComments_defaultsToOldestFirstWhenTheDirectionIsBlank() throws Exception {
        mockMvc
                .perform(get(listUrl).param("sortDirection", ""))
                .andExpectAll(status().isOk(), jsonPath("$.comments[0].body").value("oldest"));
    }

    @Test
    void listComments_rejectsAnUnknownDirectionCode() throws Exception {
        mockMvc.perform(get(listUrl).param("sortDirection", "sideways")).andExpect(status().isUnprocessableEntity());
    }
}
