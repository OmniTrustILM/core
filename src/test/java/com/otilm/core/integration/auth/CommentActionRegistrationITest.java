package com.otilm.core.integration.auth;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.auth.ContextRefreshListener;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.auth.ResourceSyncRequestDto;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The COMMENT action is enforced dynamically per host resource, so the annotation scan never sees it; the auth-service
 * sync deletes unregistered actions together with their grants. This pins the explicit registration of COMMENT for
 * every commentable resource — and for nothing else.
 */
class CommentActionRegistrationITest extends BaseSpringBootTest {

    @Autowired
    private ContextRefreshListener contextRefreshListener;

    @Test
    void commentActionIsRegisteredForEveryCommentableResource() {
        List<ResourceSyncRequestDto> resources = contextRefreshListener.getResources();

        for (Resource commentable : Resource.getCommentableResources()) {
            ResourceSyncRequestDto dto = resources
                    .stream()
                    .filter(r -> r.getName().getCode().equals(commentable.getCode()))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("Resource not synced: " + commentable.getCode()));
            assertThat(dto.getActions())
                    .as("actions of %s", commentable.getCode())
                    .contains(ResourceAction.COMMENT.getCode());
        }
    }

    @Test
    void commentActionIsNotRegisteredForNonCommentableResources() {
        assertThat(contextRefreshListener.getResources())
                .filteredOn(r -> !Resource.findByCode(r.getName().getCode()).commentable())
                .noneMatch(r -> r.getActions().contains(ResourceAction.COMMENT.getCode()));
    }

    @Test
    void commentResourceItselfCarriesNoActions() {
        assertThat(contextRefreshListener.getResources())
                .noneMatch(r -> r.getName().getCode().equals(Resource.COMMENT.getCode()));
    }
}
