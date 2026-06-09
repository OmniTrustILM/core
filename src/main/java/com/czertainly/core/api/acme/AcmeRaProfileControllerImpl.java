package com.czertainly.core.api.acme;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.acme.AcmeRaProfileController;
import com.otilm.api.model.core.acme.Account;
import com.otilm.api.model.core.acme.Authorization;
import com.otilm.api.model.core.acme.Challenge;
import com.otilm.api.model.core.acme.Directory;
import com.otilm.api.model.core.acme.Order;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.czertainly.core.aop.AuditLogged;
import com.czertainly.core.logging.LogResource;
import com.czertainly.core.service.acme.AcmeService;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

@RestController
public class AcmeRaProfileControllerImpl implements AcmeRaProfileController {

    private AcmeService acmeService;

    @Autowired
    public void setAcmeService(AcmeService acmeService) {
        this.acmeService = acmeService;
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.RA_PROFILE, operation = Operation.ACME_DIRECTORY)
    public ResponseEntity<Directory> getDirectory(@LogResource(name = true) @PathVariable String raProfileName) throws NotFoundException, AcmeProblemDocumentException {
        return acmeService.getDirectory(raProfileName, getRequestUri(),true);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.RA_PROFILE, operation = Operation.ACME_NONCE)
    public ResponseEntity<?> getNonce(@LogResource(name = true) String raProfileName) {
        return acmeService.getNonce(raProfileName, false, getRequestUri(), true);

    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.RA_PROFILE, operation = Operation.ACME_NONCE)
    public ResponseEntity<?> headNonce(@LogResource(name = true) String raProfileName) {
        return acmeService.getNonce(raProfileName, true, getRequestUri(), true);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, affiliatedResource = com.otilm.api.model.core.auth.Resource.RA_PROFILE, operation = Operation.CREATE)
    public ResponseEntity<Account> newAccount(@LogResource(name = true, affiliated = true) String raProfileName, String jwsBody) throws
            AcmeProblemDocumentException, NotFoundException {
        return acmeService.newAccount(raProfileName, jwsBody, getRequestUri(), true);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, affiliatedResource = com.otilm.api.model.core.auth.Resource.RA_PROFILE, operation = Operation.UPDATE)
    public ResponseEntity<Account> updateAccount(@LogResource(name = true, affiliated = true) String raProfileName, @LogResource(name = true) String accountId, String jwsBody)
            throws AcmeProblemDocumentException, NotFoundException {
        return acmeService.updateAccount(raProfileName, accountId, jwsBody, getRequestUri(), true);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, affiliatedResource = com.otilm.api.model.core.auth.Resource.RA_PROFILE, operation = Operation.ACME_KEY_ROLLOVER)
    public ResponseEntity<?> keyRollover(@LogResource(name = true, affiliated = true) String raProfileName, String jwsBody) throws
            NotFoundException, AcmeProblemDocumentException {
        return acmeService.keyRollover(raProfileName, jwsBody, getRequestUri(), true);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_ORDER, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, operation = Operation.CREATE)
    public ResponseEntity<Order> newOrder(String raProfileName, String jwsBody) throws
            AcmeProblemDocumentException, NotFoundException {
        return acmeService.newOrder(raProfileName, jwsBody, getRequestUri(), true);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_ORDER, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, operation = Operation.LIST)
    public ResponseEntity<List<Order>> listOrders(String raProfileName, @LogResource(name = true, affiliated = true) String accountId) throws NotFoundException, AcmeProblemDocumentException {
        return acmeService.listOrders(raProfileName, accountId, getRequestUri(), true);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_AUTHORIZATION, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_ORDER, operation = Operation.DETAIL)
    public ResponseEntity<Authorization> getAuthorizations(String raProfileName, @LogResource(name = true) String authorizationId, String jwsBody)
            throws NotFoundException, AcmeProblemDocumentException {
        return acmeService.getAuthorization(raProfileName, authorizationId, jwsBody, getRequestUri(), true);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_CHALLENGE, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_ORDER, operation = Operation.ACME_VALIDATE)
    public ResponseEntity<Challenge> validateChallenge(String raProfileName, @LogResource(name = true) String challengeId) throws
            NotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, AcmeProblemDocumentException {
        return acmeService.validateChallenge(raProfileName, challengeId, getRequestUri(), true);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_ORDER, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, operation = Operation.DETAIL)
    public ResponseEntity<Order> getOrder(String raProfileName, @LogResource(name = true) String orderId) throws NotFoundException, AcmeProblemDocumentException {
        return acmeService.getOrder(raProfileName, orderId, getRequestUri(), true);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_ORDER, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, operation = Operation.ACME_FINALIZE)
    public ResponseEntity<Order> finalizeOrder(String raProfileName, @LogResource(name = true) String orderId, String jwsBody) throws
            AcmeProblemDocumentException, ConnectorException, JsonProcessingException, CertificateException, AlreadyExistException {
        return acmeService.finalizeOrder(raProfileName, orderId, jwsBody, getRequestUri(), true);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.CERTIFICATE, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_ORDER, operation = Operation.DOWNLOAD)
    public ResponseEntity<Resource> downloadCertificate(String raProfileName, String certificateId) throws
            NotFoundException, CertificateException {
        return acmeService.downloadCertificate(raProfileName, certificateId, getRequestUri(), true);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.CERTIFICATE, affiliatedResource = com.otilm.api.model.core.auth.Resource.RA_PROFILE, operation = Operation.REVOKE)
    public ResponseEntity<?> revokeCertificate(@LogResource(name = true, affiliated = true) String raProfileName, String jwsBody) throws
            AcmeProblemDocumentException, ConnectorException, CertificateException {
        return acmeService.revokeCertificate(raProfileName, jwsBody, getRequestUri(), true);
    }

    private URI getRequestUri() {
        return ServletUriComponentsBuilder.fromCurrentRequestUri().build().toUri();
    }
}
