package com.otilm.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.model.client.attribute.RequestAttribute;

import java.security.cert.CertificateException;
import java.util.List;

public interface CertificateUploadService {

    String upload(String certificateData, List<RequestAttribute> customAttributes, boolean sync) throws CertificateException, AlreadyExistException;
}
