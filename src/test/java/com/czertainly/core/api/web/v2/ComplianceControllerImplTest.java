package com.czertainly.core.api.web.v2;

import com.otilm.api.model.core.auth.Resource;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class ComplianceControllerImplTest {

    @Test
    void mapsSubEntitiesToTheirAuthorizableOwner() {
        Assertions.assertEquals(Resource.CERTIFICATE, ComplianceControllerImpl.authorizableResource(Resource.CERTIFICATE_REQUEST));
        Assertions.assertEquals(Resource.CRYPTOGRAPHIC_KEY, ComplianceControllerImpl.authorizableResource(Resource.CRYPTOGRAPHIC_KEY_ITEM));
    }

    @Test
    void leavesAuthorizableResourcesUnchanged() {
        Assertions.assertEquals(Resource.CERTIFICATE, ComplianceControllerImpl.authorizableResource(Resource.CERTIFICATE));
        Assertions.assertEquals(Resource.SECRET, ComplianceControllerImpl.authorizableResource(Resource.SECRET));
    }
}
