package com.otilm.core.service;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.inspection.InspectionRequestDto;
import com.otilm.api.model.client.inspection.InspectionResponseDto;

/** Reads uploaded files to report what they hold. */
public interface FileInspectionExternalService {

    /**
     * Reads the uploaded file and reports its entries, storing nothing. With a token profile named, each key is
     * reported with whether the profile would take it.
     *
     * @param request the file, the passphrase that opens it, and the token profile keys would be imported into
     * @return the file's digest and its entries, in file order
     * @throws NotFoundException if the named token profile does not exist
     * @throws ValidationException with a fixed message when the file cannot be read or the profile is not a UUID
     */
    InspectionResponseDto inspect(InspectionRequestDto request) throws NotFoundException;
}
