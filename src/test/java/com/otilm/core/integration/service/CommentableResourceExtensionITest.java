package com.otilm.core.integration.service;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.service.ResourceExtensionService;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The comment service resolves host objects through {@code ResourceInternalService.getResourceObject}, which looks them
 * up in the {@code Map<String, ResourceExtensionService>} registry (bean name = resource code), so every commentable
 * resource must contribute an implementation — the read gate, the existence check and the object name for events all
 * hang off this lookup.
 */
class CommentableResourceExtensionITest extends BaseSpringBootTest {

    @Autowired
    private Map<String, ResourceExtensionService> resourceExtensionServices;

    @Test
    void everyCommentableResourceHasAnExtensionService() {
        for (Resource commentable : Resource.getCommentableResources()) {
            assertThat(resourceExtensionServices)
                    .as("extension service registered under the code of %s", commentable)
                    .containsKey(commentable.getCode());
        }
    }
}
