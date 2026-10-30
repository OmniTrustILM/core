package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.CertificateImportRequestDto;
import com.otilm.api.model.client.certificate.CertificateImportResponseDto;

/** Imports the certificates and keys an uploaded file holds. */
public interface CertificateImportExternalService {

    /**
     * Imports the entries the request names from the uploaded file, each on its own: a certificate into the inventory,
     * a key into its token profile with its certificates. Each entry is worked out again whenever it is named, so a
     * resent request imports nothing twice.
     *
     * @param request the file, the passphrase that opens it, the entries to import and where their keys go
     * @return one result per named entry, in the order they were named
     * @throws NotFoundException if a named token profile does not exist
     * @throws ValidationException with a fixed message when the file cannot be read or the selection breaks a rule
     */
    CertificateImportResponseDto importCertificates(CertificateImportRequestDto request) throws NotFoundException;
}
