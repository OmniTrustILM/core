package com.otilm.core.model.auth;

import com.otilm.api.model.core.enums.CertificateProtocol;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
public class CertificateProtocolInfo {

    private CertificateProtocol protocol;
    private UUID protocolProfileUuid;
    private UUID additionalProtocolUuid;

    public static CertificateProtocolInfo Scep(UUID scepProfileUuid) {
        CertificateProtocolInfo certificateProtocolInfo = new CertificateProtocolInfo();
        certificateProtocolInfo.setProtocol(CertificateProtocol.SCEP);
        certificateProtocolInfo.setProtocolProfileUuid(scepProfileUuid);
        return certificateProtocolInfo;
    }

    public static CertificateProtocolInfo Acme(UUID acmeProfileUuid, UUID acmeAccountUuid) {
        CertificateProtocolInfo certificateProtocolInfo = new CertificateProtocolInfo();
        certificateProtocolInfo.setProtocol(CertificateProtocol.ACME);
        certificateProtocolInfo.setProtocolProfileUuid(acmeProfileUuid);
        certificateProtocolInfo.setAdditionalProtocolUuid(acmeAccountUuid);
        return certificateProtocolInfo;
    }

    public static CertificateProtocolInfo Cmp(UUID cmpProfileUuid) {
        CertificateProtocolInfo certificateProtocolInfo = new CertificateProtocolInfo();
        certificateProtocolInfo.setProtocol(CertificateProtocol.CMP);
        certificateProtocolInfo.setProtocolProfileUuid(cmpProfileUuid);
        return certificateProtocolInfo;
    }
}
