package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.model.client.attribute.RequestAttribute;

import java.security.cert.CertificateException;
import java.util.List;

public interface CertificateUploadService {

    String upload(String certificateData, List<RequestAttribute> customAttributes, boolean sync) throws CertificateException, AlreadyExistException;
}
