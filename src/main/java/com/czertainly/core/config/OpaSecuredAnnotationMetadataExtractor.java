package com.czertainly.core.config;

import com.otilm.api.model.core.auth.Resource;
import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.ExternalAuthorizationConfigAttribute;
import com.czertainly.core.security.authz.ExternalAuthorizationDynamic;
import com.czertainly.core.security.authz.NoOpParentUUIDGetter;
import com.czertainly.core.security.authz.ParentUUIDGetter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
public class OpaSecuredAnnotationMetadataExtractor {

    Log logger = LogFactory.getLog(this.getClass());

    public List<ExternalAuthorizationConfigAttribute> extractAttributes(ExternalAuthorization secured) {
        String action = secured.action().getCode();
        String resource = secured.resource().getCode();
        String parentAction = secured.parentAction().getCode();
        String parentResource = secured.parentResource().getCode();
        Optional<Class<? extends ParentUUIDGetter>> parentUUIDGetterClass = Optional.empty();
        if (!NoOpParentUUIDGetter.class.isAssignableFrom(secured.parentObjectUUIDGetter())) {
            parentUUIDGetterClass = Optional.of(secured.parentObjectUUIDGetter());
        }

        List<ExternalAuthorizationConfigAttribute> attributes = new ArrayList<>(2);
        attributes.add(new ExternalAuthorizationConfigAttribute("action", action));
        attributes.add(new ExternalAuthorizationConfigAttribute("name", resource));
        attributes.add(new ExternalAuthorizationConfigAttribute("parentAction", parentAction));
        attributes.add(new ExternalAuthorizationConfigAttribute("parentName", parentResource));
        parentUUIDGetterClass.ifPresent(value -> attributes.add(new ExternalAuthorizationConfigAttribute("parentUUIDGetter", value)));

        logger.trace(
                "Attributes extracted from secured annotation: [%s]".formatted(
                        attributes.stream().map(ExternalAuthorizationConfigAttribute::getAttribute).collect(Collectors.joining(","))
                )
        );

        return attributes;
    }

    public List<ExternalAuthorizationConfigAttribute> extractAttributes(ExternalAuthorizationDynamic secured, Resource resolvedResource) {
        List<ExternalAuthorizationConfigAttribute> attributes = new ArrayList<>(4);
        attributes.add(new ExternalAuthorizationConfigAttribute("action", secured.action().getCode()));
        attributes.add(new ExternalAuthorizationConfigAttribute("name", resolvedResource.getCode()));
        attributes.add(new ExternalAuthorizationConfigAttribute("parentAction", secured.parentAction().getCode()));
        attributes.add(new ExternalAuthorizationConfigAttribute("parentName", secured.parentResource().getCode()));

        logger.trace(
                "Attributes extracted from dynamic secured annotation: [%s]".formatted(
                        attributes.stream().map(ExternalAuthorizationConfigAttribute::getAttribute).collect(Collectors.joining(","))
                )
        );

        return attributes;
    }
}
