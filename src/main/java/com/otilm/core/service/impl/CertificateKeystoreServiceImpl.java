package com.otilm.core.service.impl;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.certificate.CertificateKeystoreRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyExportRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.keystore.KeystoreEntry;
import com.otilm.core.keystore.Pkcs12Keystore;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.certificate.DownloadedKeystore;
import com.otilm.core.model.certificate.KeystoreSource;
import com.otilm.core.model.crypto.ExportedKeyMaterial;
import com.otilm.core.security.authz.ExternalAuthorization;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.CertificateKeystoreExternalService;
import com.otilm.core.service.CryptographicKeyExportExternalService;
import com.otilm.core.service.handler.CertificateKeystoreSource;
import java.util.Arrays;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(propagation = Propagation.NOT_SUPPORTED)
public class CertificateKeystoreServiceImpl implements CertificateKeystoreExternalService {

    static final String DOWNLOADED = "Certificate downloaded with its private key.";

    private final CertificateKeystoreSource source;
    private final CryptographicKeyExportExternalService exportService;
    private final CertificateEventHistoryInternalService eventHistoryService;

    public CertificateKeystoreServiceImpl(CertificateKeystoreSource source,
            CryptographicKeyExportExternalService exportService,
            CertificateEventHistoryInternalService eventHistoryService) {
        this.source = source;
        this.exportService = exportService;
        this.eventHistoryService = eventHistoryService;
    }

    @Override
    @ExternalAuthorization(resource = Resource.CERTIFICATE, action = ResourceAction.DETAIL)
    public DownloadedKeystore downloadKeystore(SecuredUUID uuid, CertificateKeystoreRequestDto request)
            throws NotFoundException, ConnectorException {
        KeystoreSource keystore = source.read(uuid);
        ExportedKeyMaterial exported = exported(keystore, request);
        byte[] content = Pkcs12Keystore
                .assemble(new KeystoreEntry(keystore.keyName(), exported.encryptedPrivateKeyInfo(), keystore.leaf(),
                        keystore.issuers()), request.getPassphrase());
        eventHistoryService
                .addEventHistory(keystore.certificateUuid(), CertificateEvent.DOWNLOAD_KEYSTORE,
                        CertificateEventStatus.SUCCESS, DOWNLOADED, (String) null);
        return new DownloadedKeystore(keystore.commonName(), content);
    }

    /** The private key exported under a copy of the passphrase, cleared once the export is done. */
    private ExportedKeyMaterial exported(KeystoreSource keystore, CertificateKeystoreRequestDto request)
            throws NotFoundException, ConnectorException {
        char[] characters = request.getPassphrase().characters();
        Passphrase copy = new Passphrase(characters);
        Arrays.fill(characters, '\0');
        KeyExportRequestDto export = new KeyExportRequestDto();
        export.setPassphrase(copy);
        export.setExportAttributes(request.getExportAttributes());
        try {
            return exportService.exportKey(keystore.keyUuid(), keystore.privateItemUuid(), export);
        } finally {
            copy.clear();
        }
    }
}
