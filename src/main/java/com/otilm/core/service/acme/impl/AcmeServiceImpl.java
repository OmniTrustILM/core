package com.otilm.core.service.acme.impl;

import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.core.acme.*;
import com.otilm.api.model.core.authority.CertificateRevocationReason;
import com.otilm.api.model.core.certificate.CertificateChainResponseDto;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.api.model.core.v2.ClientCertificateSignRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.acme.*;
import com.otilm.core.dao.entity.acme.*;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.czertainly.core.dao.repository.acme.*;
import com.otilm.core.dao.repository.acme.*;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateService;
import com.otilm.core.service.acme.AcmeConstants;
import com.otilm.core.service.acme.AcmeService;
import com.otilm.core.service.acme.message.AcmeJwsRequest;
import com.otilm.core.service.v2.ClientOperationService;
import com.czertainly.core.util.*;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.util.Base64URL;
import com.otilm.core.util.*;
import jakarta.transaction.Transactional;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional
public class AcmeServiceImpl implements AcmeService {

    private static final Logger logger = LoggerFactory.getLogger(AcmeServiceImpl.class);

    private AcmeNonceRepository acmeNonceRepository;
    private RaProfileRepository raProfileRepository;
    private AcmeProfileRepository acmeProfileRepository;
    private AcmeAccountRepository acmeAccountRepository;
    private AcmeOrderRepository acmeOrderRepository;
    private AcmeAuthorizationRepository acmeAuthorizationRepository;
    private AcmeChallengeRepository acmeChallengeRepository;
    private ClientOperationService clientOperationService;
    private CertificateService certificateService;
    private AttributeEngine attributeEngine;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setAcmeNonceRepository(AcmeNonceRepository acmeNonceRepository) {
        this.acmeNonceRepository = acmeNonceRepository;
    }

    @Autowired
    public void setRaProfileRepository(RaProfileRepository raProfileRepository) {
        this.raProfileRepository = raProfileRepository;
    }

    @Autowired
    public void setAcmeProfileRepository(AcmeProfileRepository acmeProfileRepository) {
        this.acmeProfileRepository = acmeProfileRepository;
    }

    @Autowired
    public void setAcmeAccountRepository(AcmeAccountRepository acmeAccountRepository) {
        this.acmeAccountRepository = acmeAccountRepository;
    }

    @Autowired
    public void setAcmeOrderRepository(AcmeOrderRepository acmeOrderRepository) {
        this.acmeOrderRepository = acmeOrderRepository;
    }

    @Autowired
    public void setAcmeAuthorizationRepository(AcmeAuthorizationRepository acmeAuthorizationRepository) {
        this.acmeAuthorizationRepository = acmeAuthorizationRepository;
    }

    @Autowired
    public void setAcmeChallengeRepository(AcmeChallengeRepository acmeChallengeRepository) {
        this.acmeChallengeRepository = acmeChallengeRepository;
    }

    @Autowired
    public void setClientOperationService(ClientOperationService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }


    @Override
    public ResponseEntity<Directory> getDirectory(String acmeProfileName, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        logger.debug("Gathering Directory information for ACME: {}", acmeProfileName);

        Directory directory = new Directory();
        String baseUri = getAcmeBaseUri();
        String replaceUrl;
        if (isRaProfileBased) {
            replaceUrl = "%s/raProfile/%s/";
        } else {
            replaceUrl = "%s/%s/";
        }
        directory.setNewNonce((replaceUrl + "new-nonce").formatted(baseUri, acmeProfileName));
        directory.setNewAccount((replaceUrl + "new-account").formatted(baseUri, acmeProfileName));
        directory.setNewOrder((replaceUrl + "new-order").formatted(baseUri, acmeProfileName));
        directory.setNewAuthz((replaceUrl + "new-authz").formatted(baseUri, acmeProfileName));
        directory.setRevokeCert((replaceUrl + "revoke-cert").formatted(baseUri, acmeProfileName));
        directory.setKeyChange((replaceUrl + "key-change").formatted(baseUri, acmeProfileName));
        try {
            directory.setMeta(frameDirectoryMeta(acmeProfileName, isRaProfileBased));
        } catch (NotFoundException e) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.SERVER_INTERNAL, "Given profile name is not found");
        }
        logger.debug("Directory information retrieved: {}", directory);

        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .body(directory);
    }

    @Override
    public ResponseEntity<?> getNonce(String acmeProfileName, Boolean isHead, URI requestUri, boolean isRaProfileBased) {
        String nonce = generateNonce();
        logger.debug("New Nonce: {}", nonce);
        ResponseEntity.HeadersBuilder<?> responseBuilder;
        if (isHead) {
            responseBuilder = ResponseEntity.ok()
                    .cacheControl(CacheControl.noStore());
        } else {
            responseBuilder = ResponseEntity.noContent()
                    .cacheControl(CacheControl.noStore());
        }

        return responseBuilder
                .header(AcmeConstants.NONCE_HEADER_NAME, nonce)
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .build();
    }

    @Override
    public ResponseEntity<Account> newAccount(String acmeProfileName, String requestJson, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        if (requestJson.isEmpty()) {
            logger.error("New Account request is empty. JWS is malformed for profile: {}", acmeProfileName);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }

        // Parse and check the JWS request
        AcmeJwsRequest jwsRequest = new AcmeJwsRequest(requestJson);
        validateRequest(jwsRequest, acmeProfileName, requestUri, isRaProfileBased);

        NewAccountRequest accountRequest = AcmeJsonProcessor.getPayloadAsRequestObject(jwsRequest.getJwsObject(), NewAccountRequest.class);
        logger.debug("New Account request: {}", accountRequest.toString());

        // Check if the Account already exists
        AcmeAccount account = acmeAccountRepository.findByPublicKey(AcmePublicKeyProcessor.publicKeyPemStringFromObject(jwsRequest.getPublicKey()));

        if (accountRequest.isOnlyReturnExisting()) {
            logger.debug("Request to only return existing Account");
            if (account == null) {
                logger.error("Requested Account does not exists");
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ACCOUNT_DOES_NOT_EXIST);
            }
        } else {
            // Create a new Account if it does not exist
            if (account == null) {
                logger.debug("Request to create a new Account");
                account = addNewAccount(acmeProfileName, AcmePublicKeyProcessor.publicKeyPemStringFromObject(jwsRequest.getPublicKey()), accountRequest, isRaProfileBased);
            }
        }

        // Check that the account is not used for different configuration
        checkAccountConfiguration(account, acmeProfileName, isRaProfileBased);

        Account accountDto = account.mapToDto();
        String baseUri = getAcmeBaseUri();
        LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, false, account.getUuid().toString(), account.getAccountId());

        ResponseEntity.BodyBuilder responseBuilder;
        if (isRaProfileBased) {
            accountDto.setOrders("%s/raProfile/%s/acct/%s/orders".formatted(baseUri, acmeProfileName, account.getAccountId()));
            if (accountRequest.isOnlyReturnExisting()) {
                responseBuilder = ResponseEntity.ok()
                        .location(URI.create("%s/raProfile/%s/acct/%s".formatted(baseUri, acmeProfileName, account.getAccountId())));
            } else {
                responseBuilder = ResponseEntity
                        .created(URI.create("%s/raProfile/%s/acct/%s".formatted(baseUri, acmeProfileName, account.getAccountId())));
            }
        } else {
            accountDto.setOrders("%s/%s/acct/%s/orders".formatted(baseUri, acmeProfileName, account.getAccountId()));
            if (accountRequest.isOnlyReturnExisting()) {
                responseBuilder = ResponseEntity.ok()
                        .location(URI.create("%s/%s/acct/%s".formatted(baseUri, acmeProfileName, account.getAccountId())));
            } else {
                responseBuilder = ResponseEntity
                        .created(URI.create("%s/%s/acct/%s".formatted(baseUri, acmeProfileName, account.getAccountId())));
            }
        }

        return responseBuilder
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.RETRY_HEADER_NAME, account.getAcmeProfile().getRetryInterval().toString())
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .body(accountDto);
    }

    @Override
    public ResponseEntity<Account> updateAccount(String acmeProfileName, String accountId, String requestJson, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        if (requestJson.isEmpty()) {
            logger.error("Update Account request is empty. JWS is malformed for profile: {}", acmeProfileName);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }

        // Parse and check the JWS request
        AcmeJwsRequest jwsRequest = new AcmeJwsRequest(requestJson);
        validateRequest(jwsRequest, acmeProfileName, requestUri, isRaProfileBased);
        validateAccount(accountId);

        logger.debug("Request to update the ACME Account with ID: {}", accountId);
        AcmeAccount account;
        try {
            account = getAcmeAccountEntity(accountId);
            LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, false, account.getUuid().toString(), account.getAccountId());
        } catch (NotFoundException e) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ACCOUNT_DOES_NOT_EXIST);
        }

        validateAccount(account);

        Account request = AcmeJsonProcessor.getPayloadAsRequestObject(jwsRequest.getJwsObject(), Account.class);
        logger.debug("Account Update request: {}", request.toString());
        if (request.getContact() != null) {
            account.setContact(SerializationUtil.serialize(request.getContact()));
        }
        if (request.getStatus() != null && request.getStatus().equals(AccountStatus.DEACTIVATED)) {
            logger.info("Deactivating Account with ID: {}", accountId);
            deactivateOrders(account);
            account.setStatus(AccountStatus.DEACTIVATED);
        }
        acmeAccountRepository.save(account);
        if (logger.isDebugEnabled()) {
            logger.debug("Updated Account: {}", account.mapToDto().toString());
        }

        return ResponseEntity.ok()
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.RETRY_HEADER_NAME, account.getAcmeProfile().getRetryInterval().toString())
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .body(account.mapToDto());
    }

    @Override
    public ResponseEntity<?> keyRollover(String acmeProfileName, String requestJson, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        if (requestJson.isEmpty()) {
            logger.error("Update Account request is empty. JWS is malformed for profile: {}", acmeProfileName);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }

        // Parse and check the JWS request
        AcmeJwsRequest jwsRequest = new AcmeJwsRequest(requestJson);
        validateRequest(jwsRequest, acmeProfileName, requestUri, isRaProfileBased);

        AcmeJwsRequest innerJws = new AcmeJwsRequest(jwsRequest.getJsonStringPayload());
        validateRequestNoNonce(innerJws, acmeProfileName, requestUri, isRaProfileBased);

        PublicKey newKey;
        PublicKey oldKey;
        try {
            String keyType = innerJws.getJwk().getKeyType().toString();
            if (keyType.equals(AcmeConstants.RSA_KEY_TYPE_NOTATION)) {
                newKey = innerJws.getJwk().toRSAKey().toPublicKey();
                oldKey = innerJws.getOldKeyJWK().toRSAKey().toPublicKey();
            } else if (keyType.equals(AcmeConstants.EC_KEY_TYPE_NOTATION)) {
                newKey = innerJws.getJwk().toECKey().toPublicKey();
                oldKey = innerJws.getOldKeyJWK().toECKey().toPublicKey();
            } else {
                logger.error("Unsupported Key Type: {}", keyType);
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED, "Unsupported Key Type");
            }
        } catch (JOSEException e) {
            logger.error("Error while parsing JWS: {}", e.getMessage());
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED, "JWS Malformed. Error while decoding the JWS Object");
        } catch (ParseException e) {
            logger.error("Error while parsing JWS: {}", e.getMessage());
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED, "Error while parsing the JWS Payload");
        }

        String account = innerJws.getJwsObject().getPayload().toJSONObject().get("account").toString();
        String accountId = account.split("/")[account.split("/").length - 1];

        AcmeAccount acmeAccount;
        try {
            acmeAccount = getAcmeAccountEntity(accountId);
            LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, false, acmeAccount.getUuid().toString(), acmeAccount.getAccountId());
        } catch (NotFoundException e) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ACCOUNT_DOES_NOT_EXIST);
        }

        validateAccount(acmeAccount);

        if (!acmeAccount.getPublicKey().equals(AcmePublicKeyProcessor.publicKeyPemStringFromObject(oldKey))) {
            logger.error("Public key of the Account with ID: {} does not match with old key in request", accountId);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.UNAUTHORIZED, "Account key does not match with old key");
        }
        AcmeAccount oldAccount = acmeAccountRepository.findByPublicKey(AcmePublicKeyProcessor.publicKeyPemStringFromObject(newKey));
        if (oldAccount != null) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .header(AcmeConstants.LOCATION_HEADER_NAME, oldAccount.getAccountId())
                    .body(new ProblemDocument("keyExists", "New Key already exists", "New key already tagged to a different account"));
        }

        validateKey(jwsRequest.getJwsObject(), innerJws.getJwsObject());

        acmeAccount.setPublicKey(AcmePublicKeyProcessor.publicKeyPemStringFromObject(newKey));
        acmeAccountRepository.save(acmeAccount);

        return ResponseEntity.ok()
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .build();
    }

    @Override
    public ResponseEntity<Order> newOrder(String acmeProfileName, String requestJson, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        if (requestJson.isEmpty()) {
            logger.error("Update Account request is empty. JWS is malformed for profile: {}", acmeProfileName);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }

        // Parse and check the JWS request
        AcmeJwsRequest jwsRequest = new AcmeJwsRequest(requestJson);
        validateRequest(jwsRequest, acmeProfileName, requestUri, isRaProfileBased);

        String[] acmeAccountKeyIdSegment = jwsRequest.getJwsObject().getHeader().getKeyID().split("/");
        String acmeAccountId = acmeAccountKeyIdSegment[acmeAccountKeyIdSegment.length - 1];
        logger.info("ACME Account ID: {}", acmeAccountId);
        AcmeAccount acmeAccount;
        try {
            acmeAccount = getAcmeAccountEntity(acmeAccountId);
            LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, true, acmeAccount.getUuid().toString(), acmeAccount.getAccountId());
            validateAccount(acmeAccount);
            logger.info("ACME Account set: {}", acmeAccount);
        } catch (NotFoundException e) {
            logger.error("Requested Account with ID {} does not exists", acmeAccountId);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ACCOUNT_DOES_NOT_EXIST);
        }

        AcmeOrder order = generateOrder(acmeAccount, jwsRequest);
        logger.debug("Order created: {}", order);
        LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ORDER, false, order.getUuid().toString(), order.getOrderId());

        return ResponseEntity.created(URI.create(order.getUrl()))
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.RETRY_HEADER_NAME, order.getAcmeAccount().getAcmeProfile().getRetryInterval().toString())
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .body(order.mapToDto());
    }

    @Override
    public ResponseEntity<List<Order>> listOrders(String acmeProfileName, String accountId, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        AcmeAccount acmeAccount;
        try {
            acmeAccount = getAcmeAccountEntity(accountId);
            LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, true, acmeAccount.getUuid().toString(), acmeAccount.getAccountId());
        } catch (NotFoundException e) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ACCOUNT_DOES_NOT_EXIST);
        }

        Integer invalidatedOrders = acmeOrderRepository.invalidateExpiredOrders(acmeAccount, new Date());
        acmeAccount.setFailedOrders(acmeAccount.getFailedOrders() + invalidatedOrders);
        acmeAccountRepository.save(acmeAccount);

        logger.debug("Request to list Orders for the Account with ID: {}", accountId);
        List<Order> orders = acmeAccount
                .getOrders()
                .stream()
                .map(AcmeOrder::mapToDto)
                .collect(Collectors.toList());
        logger.debug("Number of Orders: {}", orders.size());

        return ResponseEntity.ok()
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .body(orders);
    }

    @Override
    public ResponseEntity<Authorization> getAuthorization(String acmeProfileName, String authorizationId, String requestJson, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        if (requestJson.isEmpty()) {
            logger.error("Update Account request is empty. JWS is malformed for profile: {}", acmeProfileName);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }

        // Parse and check the JWS request
        AcmeJwsRequest jwsRequest = new AcmeJwsRequest(requestJson);
        validateRequest(jwsRequest, acmeProfileName, requestUri, isRaProfileBased);
        AcmeAuthorization authorization = validateAuthorization(authorizationId);
        LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_AUTHORIZATION, false, authorization.getUuid().toString(), authorization.getAuthorizationId());
        if (authorization.getOrder() != null) {
            LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ORDER, true, authorization.getOrder().getUuid().toString(), authorization.getOrder().getOrderId());
        }

        boolean isDeactivateRequest = false;
        if (jwsRequest.getJwsObject().getPayload().toJSONObject() != null) {
            isDeactivateRequest = jwsRequest.getJwsObject().getPayload().toJSONObject().getOrDefault("status", "") == "deactivated";
        }

        if (authorization.getExpires() != null && authorization.getExpires().before(new Date())) {
            authorization.setStatus(AuthorizationStatus.INVALID);
            acmeAuthorizationRepository.save(authorization);
        }
        if (isDeactivateRequest) {
            authorization.setStatus(AuthorizationStatus.DEACTIVATED);
            acmeAuthorizationRepository.save(authorization);
        }

        Authorization authorizationDto = authorization.mapToDto();
        logger.debug("Authorization: {}", authorizationDto.toString());

        return ResponseEntity.ok()
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .body(authorizationDto);
    }

    @Override
    public ResponseEntity<Challenge> validateChallenge(String acmeProfileName, String challengeId, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        logger.debug("Validating Challenge with ID {}:", challengeId);
        AcmeChallenge challenge = validateChallenge(challengeId);
        validateAccount(challenge.getAuthorization().getOrder().getAcmeAccount());

        AcmeAuthorization authorization = challenge.getAuthorization();
        logger.debug("Authorization corresponding to the Order: {}", authorization.toString());
        AcmeOrder order = authorization.getOrder();
        logger.debug("Order corresponding to the Challenge: {}", order.toString());
        LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ORDER, true, order.getUuid().toString(), order.getOrderId());

        boolean isValid;
        if (challenge.getType().equals(ChallengeType.HTTP01)) {
            isValid = validateHttpChallenge(challenge);
        } else {
            isValid = validateDnsChallenge(challenge);
        }

        if (isValid) {
            challenge.setValidated(new Date());
            challenge.setStatus(ChallengeStatus.VALID);
            authorization.setStatus(AuthorizationStatus.VALID);
            order.setStatus(OrderStatus.READY);
        } else {
            challenge.setStatus(ChallengeStatus.INVALID);
        }

        acmeOrderRepository.save(order);
        acmeChallengeRepository.save(challenge);
        acmeAuthorizationRepository.save(authorization);

        logger.debug("Validation of the Challenge is completed: {}", challenge);

        return ResponseEntity.ok()
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .header(AcmeConstants.LINK_HEADER_NAME, "<" + challenge.getAuthorization().getUrl() + ">;rel=\"up\"")
                .body(challenge.mapToDto());
    }

    @Override
    public ResponseEntity<Order> finalizeOrder(String acmeProfileName, String orderId, String requestJson, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        if (requestJson.isEmpty()) {
            logger.error("Update Account request is empty. JWS is malformed for profile: {}", acmeProfileName);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }

        // Parse and check the JWS request
        AcmeJwsRequest jwsRequest = new AcmeJwsRequest(requestJson);
        validateRequest(jwsRequest, acmeProfileName, requestUri, isRaProfileBased);

        logger.debug("Request to finalize the Order with ID: {}", orderId);
        AcmeOrder order = validateOrder(orderId);
        LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ORDER, false, order.getUuid().toString(), order.getOrderId());
        if (order.getAcmeAccount() != null) {
            LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, true, order.getAcmeAccount().getUuid().toString(), order.getAcmeAccount().getAccountId());
        }

        validateAccount(order.getAcmeAccount());
        logger.debug("Order found : {}", order);

        if (!order.getStatus().equals(OrderStatus.READY)) { // A request to finalize an order will result in error if the order is not in the "ready" state
            logger.error("Cannot finalize Order that is not ready.");
            throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.ORDER_NOT_READY);
        }

        // Now finalize the order
        finalizeOrder(order, jwsRequest, isRaProfileBased);

        return ResponseEntity.ok()
                .location(URI.create(order.getUrl()))
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.RETRY_HEADER_NAME, order.getAcmeAccount().getAcmeProfile().getRetryInterval().toString())
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .body(order.mapToDto());
    }

    @Transactional
    @Async
    public void finalizeOrder(AcmeOrder order, AcmeJwsRequest jwsRequest, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        logger.debug("Finalizing Order with ID: {}", order.getOrderId());
        CertificateFinalizeRequest request = AcmeJsonProcessor.getPayloadAsRequestObject(jwsRequest.getJwsObject(), CertificateFinalizeRequest.class);
        logger.debug("Finalize Order request: {}", request);

        JcaPKCS10CertificationRequest p10Object;
        String decodedCsr;
        try {
            p10Object = new JcaPKCS10CertificationRequest(Base64.getUrlDecoder().decode(request.getCsr()));
            validateCSR(p10Object, order);
            decodedCsr = CertificateRequestUtils.normalizeCsrContent(JcaPKCS10CertificationRequestToString(p10Object));
        } catch (IOException e) {
            logger.error(e.getMessage());
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_CSR);
        }

        logger.debug("Initiating issue Certificate for Order with ID: {}", order.getOrderId());
        ClientCertificateSignRequestDto certificateSignRequestDto = new ClientCertificateSignRequestDto();
        certificateSignRequestDto.setAttributes(getClientOperationAttributes(false, order.getAcmeAccount(), isRaProfileBased));
        certificateSignRequestDto.setRequest(decodedCsr);
        certificateSignRequestDto.setFormat(CertificateRequestFormat.PKCS10);
        order.setStatus(OrderStatus.PROCESSING);
        acmeOrderRepository.save(order);
        createCert(order, certificateSignRequestDto);
    }

    @Override
    public ResponseEntity<Order> getOrder(String acmeProfileName, String orderId, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        AcmeOrder order = validateOrder(orderId);
        LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ORDER, false, order.getUuid().toString(), order.getOrderId());
        if (order.getAcmeAccount() != null) {
            LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, true, order.getAcmeAccount().getUuid().toString(), order.getAcmeAccount().getAccountId());
        }

        if (order.getStatus().equals(OrderStatus.INVALID)) {
            logger.error("Order status is invalid: {}", order);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.SERVER_INTERNAL);
        }

        return ResponseEntity.ok()
                .location(URI.create(order.getUrl()))
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.RETRY_HEADER_NAME, order.getAcmeAccount().getAcmeProfile().getRetryInterval().toString())
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .body(order.mapToDto());
    }

    @Override
    public ResponseEntity<Resource> downloadCertificate(String acmeProfileName, String certificateId, URI requestUri, boolean isRaProfileBased) throws NotFoundException, CertificateException {
        logger.debug("Downloading the Certificate with ID: {}", certificateId);
        ByteArrayResource byteArrayResource = getCertificateResource(certificateId);

        return ResponseEntity.ok()
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .contentType(MediaType.valueOf("application/pem-certificate-chain"))
                .body(byteArrayResource);
    }

    @Override
    public ResponseEntity<?> revokeCertificate(String acmeProfileName, String requestJson, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException, ConnectorException, CertificateException {
        if (requestJson.isEmpty()) {
            logger.error("Update Account request is empty. JWS is malformed for profile: {}", acmeProfileName);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }

        // Parse and check the JWS request
        AcmeJwsRequest jwsRequest = new AcmeJwsRequest(requestJson);
        validateRequest(jwsRequest, acmeProfileName, requestUri, isRaProfileBased);

        CertificateRevocationRequest request = AcmeJsonProcessor.getPayloadAsRequestObject(jwsRequest.getJwsObject(), CertificateRevocationRequest.class);
        logger.debug("Certificate revocation is triggered with the payload: {}", request.toString());

        String base64UrlCertificate = request.getCertificate();
        X509Certificate x509Certificate = CertificateUtil.getX509CertificateFromBase64Url(base64UrlCertificate);
        String base64Certificate = CertificateUtil.getBase64FromX509Certificate(x509Certificate);

        ClientCertificateRevocationDto revokeRequest = new ClientCertificateRevocationDto();

        Certificate cert = certificateService.getCertificateEntityByContent(base64Certificate);
        LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.CERTIFICATE, false, cert.getUuid().toString(), cert.getSubjectDn());
        if (cert.isArchived()) throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ARCHIVED);
        if (cert.getState().equals(CertificateState.REVOKED)) {
            logger.error("Certificate is already revoked. Serial number: {}, Fingerprint: {}", cert.getSerialNumber(), cert.getFingerprint());
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ALREADY_REVOKED);
        }

        if (jwsRequest.isJwkPresent()) { // signed with the key pair of the certificate
            logger.debug("Validating revocation request signed with the key pair of the certificate");
            PublicKey certPublicKey = x509Certificate.getPublicKey();
            PublicKey jwsPublicKey = jwsRequest.getPublicKey();

            String pemPubKeyCert = AcmePublicKeyProcessor.publicKeyPemStringFromObject(certPublicKey);
            String pemPubKeyJws = AcmePublicKeyProcessor.publicKeyPemStringFromObject(jwsPublicKey);
            if (!pemPubKeyCert.equals(pemPubKeyJws)) { // check that the public key of the certificate matches the public key of the JWS
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_PUBLIC_KEY);
            }
        }

        AcmeAccount acmeAccount = null;
        if (jwsRequest.isKidPresent()) { // signed with the account key pair
            logger.debug("Validating revocation request signed with the account key pair");
            // check that the associated protocol is ACME
            if (cert.getProtocolAssociation() == null) {
                throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.UNAUTHORIZED, "Certificate is not associated with protocol");
            } else if (cert.getProtocolAssociation().getProtocol() != CertificateProtocol.ACME) {
                throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.UNAUTHORIZED, "Certificate is not associated with ACME protocol");
            }
            // check that the ACME account ID of the certificate matches the account ID in the request
            acmeAccount = acmeAccountRepository.findByUuid(cert.getProtocolAssociation().getAdditionalProtocolUuid())
                    .orElseThrow(() -> new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.UNAUTHORIZED, "Unable to find the ACME account that is associated with the certificate"));
            String kid = jwsRequest.getKid();
            String requestAccountId = kid.split("/")[kid.split("/").length - 1];
            if (!acmeAccount.getAccountId().equals(requestAccountId)) {
                throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.UNAUTHORIZED, "Account does not match the certificate associated ACME Account");
            }
        }

        // if the revocation reason is null, set it to UNSPECIFIED, otherwise get the code from the request
        final CertificateRevocationReason reason = request.getReason() == null ? CertificateRevocationReason.UNSPECIFIED : CertificateRevocationReason.fromReasonCode(request.getReason());
        // when the reason is null, it means, that is not in the list
        if (reason == null) {
            final String details = "Allowed revocation reason codes are: " + Arrays.toString(Arrays.stream(CertificateRevocationReason.values()).map(CertificateRevocationReason::getCode).toArray());
            throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.BAD_REVOCATION_REASON, details);
        }

        revokeRequest.setReason(reason);
        revokeRequest.setAttributes(getClientOperationAttributes(true, acmeAccount, isRaProfileBased));

        try {
            clientOperationService.revokeCertificate(SecuredParentUUID.fromUUID(cert.getRaProfile().getAuthorityInstanceReferenceUuid()), cert.getRaProfile().getSecuredUuid(), cert.getUuid().toString(), revokeRequest);
            return ResponseEntity
                    .ok()
                    .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                    .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                    .build();
        } catch (NotFoundException | AttributeException e) {
            return ResponseEntity
                    .badRequest()
                    .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                    .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                    .build();
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Private methods
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    private String getAcmeBaseUri() {
        return ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString() + AcmeConstants.ACME_URI_HEADER;
    }

    private DirectoryMeta frameDirectoryMeta(String profileName, boolean isRaProfileBased) throws NotFoundException {
        AcmeProfile acmeProfile;
        if (isRaProfileBased) {
            acmeProfile = getRaProfileEntity(profileName).getAcmeProfile();
        } else {
            acmeProfile = acmeProfileRepository.findByName(profileName).orElse(null);
        }
        if (acmeProfile == null) {
            throw new NotFoundException(AcmeProfile.class, profileName);
        }
        DirectoryMeta meta = new DirectoryMeta();
        meta.setCaaIdentities(new String[0]);
        meta.setTermsOfService(acmeProfile.getTermsOfServiceUrl());
        meta.setExternalAccountRequired(false);
        meta.setWebsite(acmeProfile.getWebsite());
        logger.debug("Directory meta: {}", meta);
        return meta;
    }

    private String generateNonce() {
        String nonceString = AcmeRandomGeneratorAndValidator.generateNonce();
        Date expires = AcmeCommonHelper.addSeconds(new Date(), AcmeConstants.NONCE_VALIDITY);
        AcmeNonce acmeNonce = new AcmeNonce();
        acmeNonce.setCreated(new Date());
        acmeNonce.setNonce(nonceString);
        acmeNonce.setExpires(expires);
        acmeNonceRepository.save(acmeNonce);
        return nonceString;
    }

    // RFC 8555 Section 7.1
    // The "index" link relation is present on all resources other than the
    // directory and indicates the URL of the directory.
    private String generateLinkHeader(String profileName, boolean isRaProfileBased) {
        String baseUri = getAcmeBaseUri();
        if (isRaProfileBased) {
            baseUri = baseUri + "/raProfile";
        }
        return "<" + baseUri + AcmeConstants.ACME_URI_HEADER + "/" + profileName + "/directory>;rel=\"index\"";
    }

    private AcmeAccount addNewAccount(String profileName, String publicKey, NewAccountRequest accountRequest, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        AcmeRaProfiles acmeRaProfiles = getProfiles(profileName, isRaProfileBased);
        AcmeProfile acmeProfile = acmeRaProfiles.acmeProfile;
        RaProfile raProfileToUse = acmeRaProfiles.raProfile;

        if (logger.isDebugEnabled()) {
            logger.debug("RA Profile for new Account: {}, ACME Profile: {}", raProfileToUse.toString(), acmeProfile.toString());
        }
        String accountId = AcmeRandomGeneratorAndValidator.generateRandomId();
        AcmeAccount oldAccount = acmeAccountRepository.findByPublicKey(publicKey);
        if (acmeProfile.isRequireContact() != null && acmeProfile.isRequireContact() && accountRequest.getContact().isEmpty()) {
            logger.error("Contact not found for Account: {}", accountRequest);
            {
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.INVALID_CONTACT,
                        "Contact information is missing in the Request. It is set as mandatory for this profile");
            }
        }

        if (acmeProfile.isRequireTermsOfService() != null && acmeProfile.isRequireTermsOfService() && accountRequest.isTermsOfServiceAgreed()) {
            logger.error("Terms of Service not agreed for the new Account: {}", accountRequest);
            {
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.USER_ACTION_REQUIRED,
                        "Terms of Service not agreed by the client. It is set as mandatory for this profile");
            }
        }

        if (!isRaProfileBased && acmeProfile.getRaProfile() == null) {
            logger.error("RA Profile is not associated for the ACME Profile: {}", acmeProfile);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "RA Profile is not associated for the selected ACME profile");
        }
        if (oldAccount == null) {
            if (accountRequest.isOnlyReturnExisting()) {
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ACCOUNT_DOES_NOT_EXIST);
            }
        } else {
            return oldAccount;
        }
        AcmeAccount account = new AcmeAccount();
        account.setAcmeProfile(acmeProfile);
        account.setEnabled(true);
        account.setStatus(AccountStatus.VALID);
        account.setTermsOfServiceAgreed(true);
        account.setRaProfile(raProfileToUse);
        account.setPublicKey(publicKey);
        account.setDefaultRaProfile(!isRaProfileBased);
        account.setAccountId(accountId);
        account.setContact(SerializationUtil.serialize(accountRequest.getContact()));
        acmeAccountRepository.save(account);
        logger.debug("ACME Account created: {}", account);
        return account;
    }

    private RaProfile getRaProfileEntity(String name) throws NotFoundException {
        return raProfileRepository.findByName(name).orElseThrow(() -> new NotFoundException(RaProfile.class, name));
    }

    private AcmeProfile getAcmeProfileEntityByName(String name) throws NotFoundException {
        return acmeProfileRepository.findByName(name).orElseThrow(() -> new NotFoundException(AcmeProfile.class, name));
    }

    private AcmeAccount getAcmeAccountEntity(String accountId) throws NotFoundException {
        return acmeAccountRepository.findByAccountId(accountId).orElseThrow(() -> new NotFoundException(AcmeAccount.class, accountId));
    }

    private void validateAccount(AcmeAccount acmeAccount) throws AcmeProblemDocumentException {
        if (!acmeAccount.getStatus().equals(AccountStatus.VALID)) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.UNAUTHORIZED,
                    "The requested account has been deactivated");
        }
    }

    private void deactivateOrders(AcmeAccount acmeAccount) {
        int failedOrdersCount = 0;
        for (AcmeOrder order : acmeAccount.getOrders()) {
            // Order might have already been invalid and accounted for, only update count for changed status
            if (order.getStatus() != OrderStatus.INVALID) failedOrdersCount++;
            order.setStatus(OrderStatus.INVALID);
            deactivateAuthorizations(order.getAuthorizations());
            acmeOrderRepository.save(order);
        }
        acmeAccount.setFailedOrders(acmeAccount.getFailedOrders() + failedOrdersCount);
    }

    private void deactivateAuthorizations(Set<AcmeAuthorization> authorizations) {
        for (AcmeAuthorization authorization : authorizations) {
            authorization.setStatus(AuthorizationStatus.DEACTIVATED);
            deactivateChallenges(authorization.getChallenges());
            acmeAuthorizationRepository.save(authorization);
        }   
    }

    private void deactivateChallenges(Set<AcmeChallenge> challenges) {
        for (AcmeChallenge challenge : challenges) {
            challenge.setStatus(ChallengeStatus.INVALID);
            acmeChallengeRepository.save(challenge);
        }
    }


    private void validateKey(JWSObject jwsRequestObject, JWSObject jwsInnerObject) throws AcmeProblemDocumentException {
        if (!jwsInnerObject.getHeader().toJSONObject().containsKey("jwk")) {
            throw new AcmeProblemDocumentException(
                    HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "Inner JWS does not contain jwk");
        }
        if (!jwsInnerObject.getHeader().toJSONObject().getOrDefault("url", "innerUrl")
                .equals(jwsRequestObject.getHeader().toJSONObject().getOrDefault("url", "outerUrl"))) {
            throw new AcmeProblemDocumentException(
                    HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "URL in inner and outer JWS are different");
        }
        if (jwsInnerObject.getHeader().toJSONObject().containsKey("nonce")) {
            throw new AcmeProblemDocumentException(
                    HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "Inner JWS cannot contain nonce header");
        }
    }

    private AcmeOrder generateOrder(AcmeAccount acmeAccount, AcmeJwsRequest jwsRequest) {
        logger.debug("Generating new Order for Account: {}", acmeAccount.toString());
        Order orderRequest = AcmeJsonProcessor.getPayloadAsRequestObject(jwsRequest.getJwsObject(), Order.class);
        logger.debug("Order requested: {}", orderRequest.toString());
        AcmeOrder order = new AcmeOrder();
        order.setAcmeAccount(acmeAccount);
        order.setOrderId(AcmeRandomGeneratorAndValidator.generateRandomId());
        order.setStatus(OrderStatus.PENDING);
        order.setNotAfter(AcmeCommonHelper.getDateFromString(orderRequest.getNotAfter()));
        order.setNotBefore(AcmeCommonHelper.getDateFromString(orderRequest.getNotBefore()));
        order.setIdentifiers(SerializationUtil.serializeIdentifiers(orderRequest.getIdentifiers()));
        if (acmeAccount.getAcmeProfile().getValidity() != null) {
            order.setExpires(AcmeCommonHelper.addSeconds(new Date(), acmeAccount.getAcmeProfile().getValidity()));
        } else {
            order.setExpires(AcmeCommonHelper.getDefaultExpires());
        }
        acmeOrderRepository.save(order);
        logger.debug("Order created: {}", order);

        Set<AcmeAuthorization> authorizations = generateValidations(order, orderRequest.getIdentifiers());
        order.setAuthorizations(authorizations);
        logger.debug("Challenges created for Order: {}", order);
        return order;
    }

    private Set<AcmeAuthorization> generateValidations(AcmeOrder acmeOrder, List<Identifier> identifiers) {
        Set<AcmeAuthorization> authorizations = new HashSet<>();
        for (Identifier identifier : identifiers) {
            authorizations.add(authorization(acmeOrder, identifier));
        }
        return authorizations;
    }

    private AcmeAuthorization authorization(AcmeOrder acmeOrder, Identifier identifier) {
        AcmeAuthorization authorization = new AcmeAuthorization();
        authorization.setAuthorizationId(AcmeRandomGeneratorAndValidator.generateRandomId());
        authorization.setStatus(AuthorizationStatus.PENDING);
        authorization.setOrder(acmeOrder);
        if (acmeOrder.getAcmeAccount().getAcmeProfile().getValidity() != null) {
            authorization.setExpires(AcmeCommonHelper.addSeconds(new Date(), acmeOrder.getAcmeAccount().getAcmeProfile().getValidity()));
        } else {
            authorization.setExpires(AcmeCommonHelper.getDefaultExpires());
        }
        authorization.setWildcard(checkWildcard(identifier));
        authorization.setIdentifier(SerializationUtil.serialize(identifier));
        acmeAuthorizationRepository.save(authorization);
        AcmeChallenge dnsChallenge = generateChallenge(ChallengeType.DNS01, authorization);
        AcmeChallenge httpChallenge = generateChallenge(ChallengeType.HTTP01, authorization);
        authorization.setChallenges(Set.of(dnsChallenge, httpChallenge));
        return authorization;
    }

    private boolean checkWildcard(Identifier identifier) {
        return identifier.getValue().contains("*");
    }

    private AcmeChallenge generateChallenge(ChallengeType challengeType, AcmeAuthorization authorization) {
        logger.info("Generating new Challenge for Authorization: {}", authorization.toString());
        AcmeChallenge challenge = new AcmeChallenge();
        challenge.setChallengeId(AcmeRandomGeneratorAndValidator.generateRandomId());
        challenge.setStatus(ChallengeStatus.PENDING);
        challenge.setToken(AcmeRandomGeneratorAndValidator.generateRandomTokenForValidation());
        challenge.setAuthorization(authorization);
        challenge.setType(challengeType);
        acmeChallengeRepository.save(challenge);
        return challenge;
    }

    private boolean validateHttpChallenge(AcmeChallenge challenge) throws AcmeProblemDocumentException {
        logger.debug("Initiating HTTP-01 Challenge validation: {}", challenge.toString());
        String response = getHttpChallengeResponse(
                SerializationUtil.deserializeIdentifier(
                                challenge
                                        .getAuthorization()
                                        .getIdentifier()
                        )
                        .getValue().replace("*.", ""),
                challenge.getToken());
        PublicKey pubKey;
        try {
            pubKey = AcmePublicKeyProcessor.publicKeyObjectFromString(challenge.getAuthorization().getOrder().getAcmeAccount().getPublicKey());
        } catch (Exception e) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.SERVER_INTERNAL);
        }
        String expectedResponse = AcmeCommonHelper.createKeyAuthorization(challenge.getToken(), pubKey);
        logger.debug("HTTP01 validation response from the server: {}, expected response: {}", response, expectedResponse);
        return response.equals(expectedResponse);
    }

    private boolean validateDnsChallenge(AcmeChallenge challenge) throws AcmeProblemDocumentException {
        logger.info("Initiating DNS-01 validation for challenge: {}", challenge.toString());
        Properties env = getEnv(challenge);
        List<String> txtRecords = new ArrayList<>();
        String expectedKeyAuthorization = generateDnsValidationToken(challenge.getAuthorization().getOrder().getAcmeAccount().getPublicKey(), challenge.getToken());
        DirContext context;
        try {
            context = new InitialDirContext(env);
            Attributes list = context.getAttributes(AcmeConstants.DNS_ACME_PREFIX
                            + SerializationUtil.deserializeIdentifier(
                            challenge.getAuthorization().getIdentifier()).getValue(),
                    new String[]{AcmeConstants.DNS_RECORD_TYPE});
            NamingEnumeration<? extends Attribute> records = list.getAll();

            while (records.hasMore()) {
                javax.naming.directory.Attribute record = records.next();
                txtRecords.add(record.get().toString());
            }
        } catch (NamingException e) {
            logger.error(e.getMessage());
        }
        if (txtRecords.isEmpty()) {
            logger.error("TXT record is empty for Challenge: {}", challenge);
            return false;
        }
        if (!txtRecords.contains(expectedKeyAuthorization)) {
            logger.error("TXT record not found for Challenge: {}", challenge);
            return false;
        }
        return true;
    }

    private static Properties getEnv(AcmeChallenge challenge) {
        Properties env = new Properties();
        env.setProperty(Context.INITIAL_CONTEXT_FACTORY, AcmeConstants.DNS_CONTENT_FACTORY);
        AcmeProfile acmeProfile = challenge.getAuthorization().getOrder().getAcmeAccount().getAcmeProfile();
        if (acmeProfile.getDnsResolverIp() == null || acmeProfile.getDnsResolverIp().isEmpty()) {
            env.setProperty(Context.PROVIDER_URL, AcmeConstants.DNS_ENV_PREFIX);
        } else {
            env.setProperty(Context.PROVIDER_URL, AcmeConstants.DNS_ENV_PREFIX + acmeProfile.getDnsResolverIp() + ":" + Optional.ofNullable(acmeProfile.getDnsResolverPort())
                    .orElse(AcmeConstants.DEFAULT_DNS_PORT));
        }
        return env;
    }

    private String getHttpChallengeResponse(String domain, String token) throws AcmeProblemDocumentException {
        return getResponseFollowRedirects(AcmeConstants.HTTP_CHALLENGE_BASE_URL.formatted(domain, token));
    }

    private String getResponseFollowRedirects(String url) throws AcmeProblemDocumentException {
        String finalUrl = url;
        String acmeChallengeOutput = "";
        int redirectFollowCount = 0;
        try {
            HttpURLConnection connection;
            do {
                redirectFollowCount += 1;
                URL urlObject = new URL(finalUrl);
                if (!(urlObject.getPort() == 80 || urlObject.getPort() == 443 || urlObject.getPort() == -1)) {
                    throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.TLS, "Only 80 and 443 ports can be followed");
                }
                connection = (HttpURLConnection) new URL(finalUrl).openConnection();
                connection.setInstanceFollowRedirects(false);
                connection.setUseCaches(false);
                connection.setRequestMethod(AcmeConstants.HTTP_CHALLENGE_REQUEST_METHOD);
                connection.connect();
                int responseCode = connection.getResponseCode();
                if (100 <= connection.getResponseCode() && connection.getResponseCode() <= 399) {
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                    acmeChallengeOutput = bufferedReader.lines().collect(Collectors.joining());
                }
                if (responseCode >= 300 && responseCode < 400) {
                    String redirectedUrl = connection.getHeaderField(AcmeConstants.LOCATION_HEADER_NAME);
                    if (null == redirectedUrl) {
                        break;
                    }
                    finalUrl = redirectedUrl;
                } else
                    break;
            } while (connection.getResponseCode() != HttpURLConnection.HTTP_OK && redirectFollowCount < AcmeConstants.MAX_REDIRECT_COUNT);
            connection.disconnect();
        } catch (AcmeProblemDocumentException e) {
            throw e;
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return acmeChallengeOutput;
    }

    private String generateDnsValidationToken(String publicKey, String token) throws AcmeProblemDocumentException {
        MessageDigest digest;
        try {
            PublicKey pubKey = AcmePublicKeyProcessor.publicKeyObjectFromString(publicKey);
            digest = MessageDigest.getInstance(AcmeConstants.MESSAGE_DIGEST_ALGORITHM);
            final byte[] encodedHashOfExpectedKeyAuthorization = digest.digest(AcmeCommonHelper.createKeyAuthorization(token, pubKey).getBytes(StandardCharsets.UTF_8));
            return Base64URL.encode(encodedHashOfExpectedKeyAuthorization).toString();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error(e.getMessage());
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.SERVER_INTERNAL);
        }
    }

    private void validateCSR(JcaPKCS10CertificationRequest csr, AcmeOrder order) throws AcmeProblemDocumentException {
        List<String> sans = new ArrayList<>();
        List<String> dnsIdentifiers = new ArrayList<>();

        org.bouncycastle.asn1.pkcs.Attribute[] certAttributes = csr.getAttributes();
        try {
            String commonName = IETFUtils.valueToString(csr.getSubject().getRDNs(BCStyle.CN)[0].getFirst().getValue());
            if (!commonName.isEmpty()) {
                sans.add(commonName);
                dnsIdentifiers.add(commonName);
            }

        } catch (Exception e) {
            logger.warn("Unable to find common name: {}", e.getMessage());
        }
        for (org.bouncycastle.asn1.pkcs.Attribute attribute : certAttributes) {
            if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                Extensions extensions = Extensions.getInstance(attribute.getAttrValues().getObjectAt(0));
                GeneralNames gns = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
                if (gns != null) {
                    GeneralName[] names = gns.getNames();
                    for (GeneralName name : names) {
                        if (name.getTagNo() == GeneralName.dNSName) {
                            dnsIdentifiers.add(IETFUtils.valueToString(name.getName()));
                        }
                        sans.add(IETFUtils.valueToString(name.getName()));
                    }
                }
            }
        }

        List<String> identifiers = SerializationUtil.deserializeIdentifiers(order.getIdentifiers())
                .stream()
                .map(Identifier::getValue)
                .toList();

        List<String> identifiersDns = new ArrayList<>();
        for (Identifier identifier : SerializationUtil.deserializeIdentifiers(order.getIdentifiers())) {
            if (identifier.getType().equals("dns")) {
                identifiersDns.add(identifier.getValue());
            }
        }

        if (!new HashSet<>(sans).containsAll(identifiers)) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_CSR);
        }
        if (!new HashSet<>(dnsIdentifiers).containsAll(identifiersDns)) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_CSR);
        }
    }

    private String JcaPKCS10CertificationRequestToString(JcaPKCS10CertificationRequest csr) throws IOException {
        PemObject pemCSR = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
        StringWriter decodedCsr = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(decodedCsr);
        pemWriter.writeObject(pemCSR);
        pemWriter.close();
        decodedCsr.close();
        return decodedCsr.toString();
    }

    private List<RequestAttribute> getClientOperationAttributes(boolean isRevoke, AcmeAccount acmeAccount, boolean isRaProfileBased) {
        if (acmeAccount == null) {
            return List.of();
        }

        if (isRaProfileBased) {
            String attributes;
            if (isRevoke) {
                attributes = acmeAccount.getRaProfile().getProtocolAttribute().getAcmeRevokeCertificateAttributes();
            } else {
                attributes = acmeAccount.getRaProfile().getProtocolAttribute().getAcmeIssueCertificateAttributes();
            }
            return AttributeDefinitionUtils.getClientAttributes(AttributeDefinitionUtils.deserialize(attributes, DataAttributeV2.class));
        } else {
            if (isRevoke) {
                return attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(com.otilm.api.model.core.auth.Resource.ACME_PROFILE, acmeAccount.getAcmeProfile().getUuid()).connector(acmeAccount.getAcmeProfile().getRaProfile().getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_REVOKE).build());
            } else {
                return attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(com.otilm.api.model.core.auth.Resource.ACME_PROFILE, acmeAccount.getAcmeProfile().getUuid()).connector(acmeAccount.getAcmeProfile().getRaProfile().getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_ISSUE).build());
            }
        }

    }

    private void createCert(AcmeOrder order, ClientCertificateSignRequestDto certificateSignRequestDto) {
        // check if certificate is not already requested (prevent calling finalize multiple times issuing more certificates)
        // not sure if it is necessary
        if (order.getCertificateReference() == null) {
            try {
                // keep state as PROCESSING since issuing is async process
                if (logger.isDebugEnabled()) {
                    logger.debug("Requesting Certificate for the Order: {} and certificate signing request: {}", order, certificateSignRequestDto);
                }
                ClientCertificateDataResponseDto certificateOutput = clientOperationService.issueCertificate(SecuredParentUUID.fromUUID(order.getAcmeAccount().getRaProfile().getAuthorityInstanceReferenceUuid()), order.getAcmeAccount().getRaProfile().getSecuredUuid(), certificateSignRequestDto,
                        CertificateProtocolInfo.Acme(order.getAcmeAccount().getAcmeProfileUuid(), order.getAcmeAccountUuid()));
                order.setCertificateId(AcmeRandomGeneratorAndValidator.generateRandomId());
                order.setCertificateReference(certificateService.getCertificateEntity(SecuredUUID.fromString(certificateOutput.getUuid())));
            } catch (Exception e) {
                logger.error("Issue Certificate failed. Exception: {}", e.getMessage());
                order.setStatus(OrderStatus.INVALID);
                // Order with previously invalid status would not have reached issuing of certificate, therefore count needs to be incremented always
                incrementFailedOrdersCount(order);
            }
            acmeOrderRepository.save(order);
        } else {
            OrderStatus newStatus = checkOrderStatusByCertificate(order.getCertificateReference());
            logger.debug("Calling finalize of Order but certificate is already requested. Current status: {}", newStatus);
            if (!newStatus.equals(order.getStatus())) {
                order.setStatus(newStatus);
                incrementOrderCounts(newStatus, order);
                acmeOrderRepository.save(order);
            }
        }
    }

    private OrderStatus checkOrderStatusByCertificate(Certificate certificate) {
        if (certificate.getState().equals(CertificateState.ISSUED)) return OrderStatus.VALID;
        if (certificate.getState().equals(CertificateState.REQUESTED)
                || certificate.getState().equals(CertificateState.PENDING_APPROVAL)
                || certificate.getState().equals(CertificateState.PENDING_ISSUE)) return OrderStatus.PROCESSING;

        return OrderStatus.INVALID;
    }

    protected ByteArrayResource getCertificateResource(String certificateId) throws NotFoundException, CertificateException {
        AcmeOrder order = acmeOrderRepository.findByCertificateId(certificateId).orElseThrow(() -> new NotFoundException(Order.class, certificateId));
        LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ORDER, true, order.getUuid().toString(), order.getOrderId());

        CertificateChainResponseDto certificateChainResponse = certificateService.getCertificateChain(SecuredUUID.fromUUID(order.getCertificateReferenceUuid()), true);
        if (!certificateChainResponse.getCertificates().isEmpty()) {
            LoggingHelper.putLogResourceInfo(com.otilm.api.model.core.auth.Resource.CERTIFICATE, false, certificateChainResponse.getCertificates().getFirst().getUuid(), certificateChainResponse.getCertificates().getFirst().getSubjectDn());
        }
        String chainString = frameCertChainString(certificateChainResponse.getCertificates());
        return new ByteArrayResource(chainString.getBytes(StandardCharsets.UTF_8));
    }

    protected String frameCertChainString(List<CertificateDetailDto> certificates) throws CertificateException {
        List<String> chain = new ArrayList<>();
        for (CertificateDetailDto certificate : certificates) {
            chain.add(X509ObjectToString.toPem(getX509(certificate.getCertificateContent())));
        }
        return String.join("\r\n", chain);
    }

    private X509Certificate getX509(String certificate) throws CertificateException {
        return CertificateUtil.getX509Certificate(CertificateUtil.normalizeCertificateContent(certificate));
    }

    private void checkAccountConfiguration(AcmeAccount account, String profileName, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        AcmeRaProfiles acmeRaProfiles = getProfiles(profileName, isRaProfileBased);

        if (!account.getAcmeProfileUuid().equals(acmeRaProfiles.acmeProfile.getUuid()) ||
                !account.getRaProfileUuid().equals(acmeRaProfiles.raProfile.getUuid())) {
            throw new AcmeProblemDocumentException(HttpStatus.UNAUTHORIZED, Problem.UNAUTHORIZED, "Account does not belong to this profile");
        }
    }

    private AcmeRaProfiles getProfiles(String profileName, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        AcmeProfile acmeProfile;
        RaProfile raProfileToUse;

        if (isRaProfileBased) {
            try {
                raProfileToUse = getRaProfileEntity(profileName);
            } catch (NotFoundException e) {
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED, "RA Profile is not found");
            }
            acmeProfile = raProfileToUse.getAcmeProfile();
        } else {
            try {
                acmeProfile = getAcmeProfileEntityByName(profileName);
            } catch (NotFoundException e) {
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED, "ACME Profile is not found");
            }
            raProfileToUse = acmeProfile.getRaProfile();
        }

        return new AcmeRaProfiles(acmeProfile, raProfileToUse);
    }

    private record AcmeRaProfiles(AcmeProfile acmeProfile, RaProfile raProfile) {}

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Validation of ACME requests
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    private void validateRequest(AcmeJwsRequest acmeJwsRequest, String acmeProfileName, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        validateRequestNoNonce(acmeJwsRequest, acmeProfileName, requestUri, isRaProfileBased);

        //Validate JWS Header for Nonce if it has the correct value
        validateNonce(acmeJwsRequest.getJwsHeader().getCustomParam("nonce"));
    }

    private void validateRequestNoNonce(AcmeJwsRequest acmeJwsRequest, String acmeProfileName, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        if (acmeJwsRequest.getJwsHeader() == null) {
            logger.error("JWS header is missing or malformed");
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }

        acmeJwsRequest.validateUrl(requestUri.toString());

        validateSignature(acmeJwsRequest);

        if (isRaProfileBased) {
            validateRaBasedAcme(acmeProfileName);
        } else {
            validateAcme(acmeProfileName);
        }
    }

    private void validateNonce(Object nonce) throws AcmeProblemDocumentException {
        if (nonce == null) {
            logger.error("Nonce is not found in the request");
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_NONCE);
        }

        AcmeNonce acmeNonce = acmeNonceRepository.findByNonce(nonce.toString()).orElseThrow(
                () -> new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_NONCE));
        if (acmeNonce.getExpires().after(AcmeCommonHelper.addSeconds(new Date(), AcmeConstants.NONCE_VALIDITY))) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_NONCE);
        }
    }

    private void validateSignature(AcmeJwsRequest acmeJwsRequest) throws AcmeProblemDocumentException {
        if (acmeJwsRequest.isJwkPresent()) {
            acmeJwsRequest.checkSignature(acmeJwsRequest.getPublicKey());
        } else {
            String kid = acmeJwsRequest.getKid();
            AcmeAccount account = acmeAccountRepository.findByAccountId(
                            kid.split("/")[kid.split("/").length - 1])
                    .orElseThrow(
                            () -> new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ACCOUNT_DOES_NOT_EXIST));
            PublicKey publicKey;
            try {
                publicKey = AcmePublicKeyProcessor.publicKeyObjectFromString(account.getPublicKey());
                if (!acmeJwsRequest.checkSignature(publicKey)) {
                    throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.UNAUTHORIZED);
                }
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                logger.error(e.getMessage());
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_PUBLIC_KEY);
            }
        }
    }

    public void validateRaBasedAcme(String raProfileName) throws AcmeProblemDocumentException {
        RaProfile raProfile = raProfileRepository.findByName(raProfileName).orElseThrow(() ->
                new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                        "Given RA Profile in the request URL is not found"));
        if (raProfile.getAcmeProfile() == null) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "ACME Profile is not associated with the RA Profile");
        }
        if (!raProfile.getEnabled()) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "RA Profile is not enabled");
        }

        if (!raProfile.getAcmeProfile().isEnabled()) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "ACME Profile is not enabled");
        }
    }

    private void validateAcme(String acmeProfileName) throws AcmeProblemDocumentException {
        AcmeProfile acmeProfile = acmeProfileRepository.findByName(acmeProfileName).orElse(null);
        if (acmeProfile == null) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "Given ACME Profile in the request URL is not found");
        }

        if (!acmeProfile.isEnabled()) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "ACME Profile is not enabled");
        }
        if (acmeProfile.getRaProfile() == null) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "RA Profile is not found");
        }
        if (!acmeProfile.getRaProfile().getEnabled()) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "RA Profile is not enabled");
        }
        if (acmeProfile.isDisableNewOrders()) {
            ProblemDocument problemDocument = new ProblemDocument(Problem.USER_ACTION_REQUIRED);
            problemDocument.setInstance(acmeProfile.getTermsOfServiceUrl());
            problemDocument.setDetail("Terms of service have changed");
            Map<String, String> additionalHeaders = new HashMap<>();
            additionalHeaders.put("Link", "<" + acmeProfile.getTermsOfServiceChangeUrl() + ">;rel=\"terms-of-service\"");
            throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, problemDocument, additionalHeaders);
        }
    }

    private AcmeOrder validateOrder(String orderId) throws AcmeProblemDocumentException {
        AcmeOrder order = acmeOrderRepository.findByOrderId(orderId).orElseThrow(() -> new
                AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.SERVER_INTERNAL,
                "Requested order is not found"));

        if (order.getExpires() != null) {
            if (order.getExpires().before(new Date())) {
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                        "Expiry of the order is reached");
            }
        }

        // check for status if certificate reference is set
        if (order.getCertificateReference() != null) {
            OrderStatus newStatus = checkOrderStatusByCertificate(order.getCertificateReference());
            if (!newStatus.equals(order.getStatus())) {
                logger.info("ACME Order status changed from {} to {}.", order.getStatus(), newStatus);
                order.setStatus(newStatus);
                incrementOrderCounts(newStatus, order);
                acmeOrderRepository.save(order);
            }
        }

        return order;
    }

    private void incrementOrderCounts(OrderStatus newStatus, AcmeOrder order) {
        // Since this method is called only if the order status has been changed, the count of failed/valid orders will
        // always need to be updated
        if (newStatus == OrderStatus.INVALID) {
            incrementFailedOrdersCount(order);
        }
        if (newStatus == OrderStatus.VALID) {
            order.getAcmeAccount().setValidOrders(order.getAcmeAccount().getValidOrders() + 1);
            acmeAccountRepository.save(order.getAcmeAccount());
        }
    }

    private void incrementFailedOrdersCount(AcmeOrder order) {
        order.getAcmeAccount().setFailedOrders(order.getAcmeAccount().getFailedOrders() + 1);
        acmeAccountRepository.save(order.getAcmeAccount());
    }

    private AcmeAuthorization validateAuthorization(String authorizationId) throws AcmeProblemDocumentException {
        AcmeAuthorization authorization = acmeAuthorizationRepository.findByAuthorizationId(authorizationId)
                .orElseThrow(() -> new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST,
                        Problem.SERVER_INTERNAL, "Requested authorization is not found"));
        if (authorization.getExpires() != null) {
            if (authorization.getExpires().before(new Date())) {
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                        "Expiry of the authorization is reached");
            }
        }
        return authorization;
    }

    private AcmeChallenge validateChallenge(String challengeId) throws AcmeProblemDocumentException {
        AcmeChallenge challenge = acmeChallengeRepository.findByChallengeId(challengeId)
                .orElseThrow(() -> new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST,
                        Problem.SERVER_INTERNAL, "Requested challenge is not found"));
        if (challenge.getAuthorization().getExpires() != null) {
            if (challenge.getAuthorization().getExpires().before(new Date())) {
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST,
                        Problem.MALFORMED, "Challenge is expired");
            }
        }
        return challenge;
    }

    private void validateAccount(String accountId) throws AcmeProblemDocumentException {
        AcmeAccount acmeAccount = acmeAccountRepository.findByAccountId(accountId)
                .orElseThrow(() ->
                        new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ACCOUNT_DOES_NOT_EXIST));
        validateAccount(acmeAccount);
    }

}
