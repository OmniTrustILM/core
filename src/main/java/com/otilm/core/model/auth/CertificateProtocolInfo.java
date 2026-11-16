package com.otilm.core.model.auth;

import com.otilm.api.model.core.enums.CertificateProtocol;
import java.util.UUID;
import java.util.function.Consumer;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CertificateProtocolInfo {

    private CertificateProtocol protocol;
    private UUID protocolProfileUuid;
    private UUID additionalProtocolUuid;

    /**
     * Run inside the transaction that stores the certificate, once its row exists, with the certificate's UUID; a throw
     * rolls the store back. Null when the protocol needs no such step.
     */
    private Consumer<UUID> onStored;

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

    public static CertificateProtocolInfo est(UUID estProfileUuid) {
        return est(estProfileUuid, null);
    }

    public static CertificateProtocolInfo est(UUID estProfileUuid, Consumer<UUID> onStored) {
        CertificateProtocolInfo certificateProtocolInfo = new CertificateProtocolInfo();
        certificateProtocolInfo.setProtocol(CertificateProtocol.EST);
        certificateProtocolInfo.setProtocolProfileUuid(estProfileUuid);
        certificateProtocolInfo.setOnStored(onStored);
        return certificateProtocolInfo;
    }
}
