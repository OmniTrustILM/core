package com.otilm.core.service.est;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.certificate.request.CsrAttrsEncoder;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.service.RaProfileCertificateRequestAttributeService;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Service
public class EstCsrAttrsServiceImpl implements EstCsrAttrsService {

    private final RaProfileCertificateRequestAttributeService requestAttributeService;

    public EstCsrAttrsServiceImpl(RaProfileCertificateRequestAttributeService requestAttributeService) {
        this.requestAttributeService = requestAttributeService;
    }

    @Override
    public byte[] buildCsrAttrs(RaProfile raProfile) throws ConnectorException, NotFoundException, IOException {
        List<BaseAttribute> definitions = requestAttributeService.resolveIssueAttributeSet(raProfile);
        return CsrAttrsEncoder.encode(definitions, codeToOid());
    }

    /** Seam for tests; production reads the RDN code→OID map from the startup-populated OID cache. */
    protected Map<String, String> codeToOid() {
        return OidHandler.getCodeToOidMap();
    }
}
