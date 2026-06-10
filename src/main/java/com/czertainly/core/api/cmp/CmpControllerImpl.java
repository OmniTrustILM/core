package com.czertainly.core.api.cmp;

import com.otilm.api.interfaces.core.cmp.CmpController;
import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.interfaces.core.cmp.error.ImplFailureInfo;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.service.cmp.CmpService;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CmpControllerImpl implements CmpController {

    private CmpService cmpService;

    @Autowired
    public void setCmpService(CmpService cmpService) {
        this.cmpService = cmpService;
    }

    /**
     * Handling of GET is not allowed - http 500 is returned
     *
     * @param cmpProfileName customer-based configuration name
     * @param request        binary {@link org.bouncycastle.asn1.cmp.PKIMessage}
     * @return http status 500 because of http get is not allowed
     * @throws CmpBaseException - http get is not allowed
     */
    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.CERTIFICATE, affiliatedResource = Resource.CMP_PROFILE, operation = Operation.UNKNOWN)
    public ResponseEntity<byte[]> doGet(@LogResource(name = true, affiliated = true) String cmpProfileName, byte[] request) throws CmpBaseException {
        throw new CmpProcessingException(PKIFailureInfo.badRequest, ImplFailureInfo.CMPCNTR001);
    }

    /**
     * Handling pki request/response flow
     *
     * @param cmpProfileName customer-based configuration name
     * @param request        binary {@link org.bouncycastle.asn1.cmp.PKIMessage}
     * @return response for given <code>request</code>
     * @throws CmpBaseException if any error has been raised
     */
    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = Resource.CERTIFICATE, affiliatedResource = Resource.CMP_PROFILE, operation = Operation.UNKNOWN)
    public ResponseEntity<byte[]> doPost(@LogResource(name = true, affiliated = true) String cmpProfileName, byte[] request) throws CmpBaseException {
        return cmpService.handlePost(cmpProfileName, request);
    }
}
