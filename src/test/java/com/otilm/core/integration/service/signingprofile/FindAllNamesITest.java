package com.otilm.core.integration.service.signingprofile;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.core.service.signingprofile.SigningProfileTestBase;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class FindAllNamesITest extends SigningProfileTestBase {

    @Test
    void testFindAllNames_returnsExistingNames() {
        // given
        // savedProfile exists from setUp

        // when
        List<String> names = signingProfileInternalService.findAllNames();

        // then
        Assertions.assertNotNull(names);
        Assertions.assertEquals(1, names.size());
        Assertions.assertTrue(names.contains(savedProfile.getName()));
    }

    @Test
    void testFindAllNames_returnsAllWhenMultipleExist()
            throws AlreadyExistException, AttributeException, ConnectorException, NotFoundException {
        // given
        signingProfileService.createSigningProfile(buildDelegatedRawRequest("second-signing-profile"));

        // when
        List<String> names = signingProfileInternalService.findAllNames();

        // then
        Assertions.assertEquals(2, names.size());
        Assertions.assertTrue(names.contains(savedProfile.getName()));
        Assertions.assertTrue(names.contains("second-signing-profile"));
    }

    @Test
    void testFindAllNames_emptyWhenNoneExist() throws NotFoundException {
        // given
        signingProfileService.deleteSigningProfile(savedProfile.getSecuredUuid());

        // when
        List<String> names = signingProfileInternalService.findAllNames();

        // then
        Assertions.assertNotNull(names);
        Assertions.assertTrue(names.isEmpty());
    }
}
