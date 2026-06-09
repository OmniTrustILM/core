package com.otilm.core.security.authz;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.UUID;

class SecuredResourceTest {

    @Test
    void wrapsAndUnwrapsResource() {
        SecuredResource secured = SecuredResource.fromResource(Resource.CERTIFICATE);
        Assertions.assertEquals(Resource.CERTIFICATE, secured.getResource());
    }

    @Test
    void fromResourceReturnsNullForNull() {
        Assertions.assertNull(SecuredResource.fromResource(null));
    }

    @Test
    void resolvesTheSingleSecuredResourceArgument() {
        SecuredResource resolved = SecuredResource.fromArguments(
                new Object[]{SecuredResource.fromResource(Resource.RA_PROFILE), UUID.randomUUID(), "ignored"});
        Assertions.assertEquals(Resource.RA_PROFILE, resolved.getResource());
    }

    @Test
    void ignoresBareResourceArgumentsWhenResolving() {
        // A bare Resource (data, not the auth subject) must NOT be picked up.
        SecuredResource resolved = SecuredResource.fromArguments(
                new Object[]{Resource.CERTIFICATE_REQUEST, SecuredResource.fromResource(Resource.CERTIFICATE)});
        Assertions.assertEquals(Resource.CERTIFICATE, resolved.getResource());
    }

    @Test
    void throwsWhenNoSecuredResourceArgumentPresent() {
        Object[] arguments = new Object[]{Resource.CERTIFICATE, UUID.randomUUID()};
        Assertions.assertThrows(ValidationException.class,
                () -> SecuredResource.fromArguments(arguments));
    }

    @Test
    void throwsWhenMoreThanOneSecuredResourceArgumentPresent() {
        Object[] arguments = new Object[]{
                SecuredResource.fromResource(Resource.CERTIFICATE),
                SecuredResource.fromResource(Resource.RA_PROFILE)};
        Assertions.assertThrows(ValidationException.class,
                () -> SecuredResource.fromArguments(arguments));
    }
}
