package com.otilm.core.api.acme;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.acme.AcmeController;
import com.otilm.api.model.core.acme.Account;
import com.otilm.api.model.core.acme.Authorization;
import com.otilm.api.model.core.acme.Challenge;
import com.otilm.api.model.core.acme.Directory;
import com.otilm.api.model.core.acme.Order;
import com.otilm.api.model.core.logging.enums.Module;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.core.aop.AuditLogged;
import com.otilm.core.logging.LogResource;
import com.otilm.core.service.acme.AcmeExternalService;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

@RestController
public class AcmeControllerImpl implements AcmeController {

    private AcmeExternalService acmeService;

    @Autowired
    public void setAcmeService(AcmeExternalService acmeService) {
        this.acmeService = acmeService;
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_PROFILE, operation = Operation.ACME_DIRECTORY)
    public ResponseEntity<Directory> getDirectory(@LogResource(name = true) String acmeProfileName) throws NotFoundException, AcmeProblemDocumentException {
        return acmeService.getDirectory(acmeProfileName, getRequestUri(), false);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_PROFILE, operation = Operation.ACME_NONCE)
    public ResponseEntity<?> getNonce(@LogResource(name = true) String acmeProfileName) {
        return acmeService.getNonce(acmeProfileName, false, getRequestUri(), false);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_PROFILE, operation = Operation.ACME_NONCE)
    public ResponseEntity<?> headNonce(@LogResource(name = true) String acmeProfileName) {
        return acmeService.getNonce(acmeProfileName, true, getRequestUri(), false);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_PROFILE, operation = Operation.CREATE)
    public ResponseEntity<Account> newAccount(@LogResource(name = true, affiliated = true) String acmeProfileName, String jwsBody) throws
            AcmeProblemDocumentException, NotFoundException {
        return acmeService.newAccount(acmeProfileName, jwsBody, getRequestUri(), false);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_PROFILE, operation = Operation.UPDATE)
    public ResponseEntity<Account> updateAccount(@LogResource(name = true, affiliated = true) String acmeProfileName, @LogResource(name = true) String accountId, String jwsBody) throws
            AcmeProblemDocumentException, NotFoundException {
        return acmeService.updateAccount(acmeProfileName, accountId, jwsBody, getRequestUri(), false);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_PROFILE, operation = Operation.ACME_KEY_ROLLOVER)
    public ResponseEntity<?> keyRollover(@LogResource(name = true, affiliated = true) String acmeProfileName, String jwsBody) throws
            NotFoundException, AcmeProblemDocumentException {
        return acmeService.keyRollover(acmeProfileName, jwsBody, getRequestUri(), false);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_ORDER, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, operation = Operation.CREATE)
    public ResponseEntity<Order> newOrder(String acmeProfileName, String jwsBody) throws
            AcmeProblemDocumentException, NotFoundException {
        return acmeService.newOrder(acmeProfileName, jwsBody, getRequestUri(), false);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_ORDER, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, operation = Operation.LIST)
    public ResponseEntity<List<Order>> listOrders(String acmeProfileName, @LogResource(name = true, affiliated = true) String accountId) throws
            NotFoundException, AcmeProblemDocumentException {
        return acmeService.listOrders(acmeProfileName, accountId, getRequestUri(), false);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_AUTHORIZATION, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_ORDER, operation = Operation.DETAIL)
    public ResponseEntity<Authorization> getAuthorizations(String acmeProfileName, @LogResource(name = true) String authorizationId, String jwsBody)
            throws NotFoundException, AcmeProblemDocumentException {
        return acmeService.getAuthorization(acmeProfileName, authorizationId, jwsBody, getRequestUri(), false);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_CHALLENGE, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_ORDER, operation = Operation.ACME_VALIDATE)
    public ResponseEntity<Challenge> validateChallenge(String acmeProfileName, @LogResource(name = true) String challengeId)
            throws NotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, AcmeProblemDocumentException {
        return acmeService.validateChallenge(acmeProfileName, challengeId, getRequestUri(), false);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_ORDER, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, operation = Operation.DETAIL)
    public ResponseEntity<Order> getOrder(String acmeProfileName, @LogResource(name = true) String orderId) throws NotFoundException, AcmeProblemDocumentException {
        return acmeService.getOrder(acmeProfileName, orderId, getRequestUri(), false);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.ACME_ORDER, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, operation = Operation.ACME_FINALIZE)
    public ResponseEntity<Order> finalizeOrder(String acmeProfileName, @LogResource(name = true) String orderId, String jwsBody) throws
            AcmeProblemDocumentException, ConnectorException, JsonProcessingException, CertificateException, AlreadyExistException {
        return acmeService.finalizeOrder(acmeProfileName, orderId, jwsBody, getRequestUri(), false);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.CERTIFICATE, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_ORDER, operation = Operation.DOWNLOAD)
    public ResponseEntity<Resource> downloadCertificate(String acmeProfileName, String certificateId) throws
            NotFoundException, CertificateException {
        return acmeService.downloadCertificate(acmeProfileName, certificateId, getRequestUri(), false);
    }

    @Override
    @AuditLogged(module = Module.PROTOCOLS, resource = com.otilm.api.model.core.auth.Resource.CERTIFICATE, affiliatedResource = com.otilm.api.model.core.auth.Resource.ACME_PROFILE, operation = Operation.REVOKE)
    public ResponseEntity<?> revokeCertificate(@LogResource(name = true, affiliated = true) String acmeProfileName, String jwsBody) throws
            AcmeProblemDocumentException, ConnectorException, CertificateException {
        return acmeService.revokeCertificate(acmeProfileName, jwsBody, getRequestUri(), false);
    }

    private URI getRequestUri() {
        return ServletUriComponentsBuilder.fromCurrentRequestUri().build().toUri();
    }
}
