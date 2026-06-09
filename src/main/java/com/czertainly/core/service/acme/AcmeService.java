package com.czertainly.core.service.acme;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.acme.Account;
import com.otilm.api.model.core.acme.Authorization;
import com.otilm.api.model.core.acme.Challenge;
import com.otilm.api.model.core.acme.Directory;
import com.otilm.api.model.core.acme.Order;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public interface AcmeService {
    ResponseEntity<Directory> getDirectory(String acmeProfileName, URI requestUri, boolean isRaProfileBased) throws NotFoundException, AcmeProblemDocumentException;

    ResponseEntity<?> getNonce(String acmeProfileName, Boolean isHead, URI requestUri, boolean isRaProfileBased);

    ResponseEntity<Account> newAccount(String acmeProfileName, String requestJson, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException, NotFoundException;

    ResponseEntity<Account> updateAccount(String acmeProfileName, String accountId, String requestJson, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException, NotFoundException;

    ResponseEntity<?> keyRollover(String acmeProfileName, String jwsBody, URI requestUri, boolean isRaProfileBased) throws NotFoundException, AcmeProblemDocumentException;

    ResponseEntity<Order> newOrder(String acmeProfileName, String requestJson, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException, NotFoundException;

    ResponseEntity<List<Order>> listOrders(String acmeProfileName, String accountId, URI requestUri, boolean isRaProfileBased) throws NotFoundException, AcmeProblemDocumentException;

    ResponseEntity<Authorization> getAuthorization(String acmeProfileName, String authorizationId, String jwsBody, URI requestUri, boolean isRaProfileBased) throws NotFoundException, AcmeProblemDocumentException;

    ResponseEntity<Challenge> validateChallenge(String acmeProfileName, String challengeId, URI requestUri, boolean isRaProfileBased) throws NotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, AcmeProblemDocumentException;

    ResponseEntity<Order> finalizeOrder(String acmeProfileName, String orderId, String jwsBody, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException, ConnectorException, JsonProcessingException, CertificateException, AlreadyExistException;

    ResponseEntity<Order> getOrder(String acmeProfileName, String orderId, URI requestUri, boolean isRaProfileBased) throws NotFoundException, AcmeProblemDocumentException;

    ResponseEntity<Resource> downloadCertificate(String acmeProfileName, String certificateId, URI requestUri, boolean isRaProfileBased) throws NotFoundException, CertificateException;

    ResponseEntity<?> revokeCertificate(String acmeProfileName, String jwsBody, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException, ConnectorException, CertificateException;

}
