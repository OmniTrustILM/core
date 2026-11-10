package com.otilm.core.service.acme.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.otilm.api.exception.AcmeProblemDocumentException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.core.acme.Account;
import com.otilm.api.model.core.acme.AccountStatus;
import com.otilm.api.model.core.acme.AcmeIdentifierAuthorizationMode;
import com.otilm.api.model.core.acme.Authorization;
import com.otilm.api.model.core.acme.AuthorizationStatus;
import com.otilm.api.model.core.acme.CertificateFinalizeRequest;
import com.otilm.api.model.core.acme.CertificateRevocationRequest;
import com.otilm.api.model.core.acme.Challenge;
import com.otilm.api.model.core.acme.ChallengeStatus;
import com.otilm.api.model.core.acme.ChallengeType;
import com.otilm.api.model.core.acme.Directory;
import com.otilm.api.model.core.acme.DirectoryMeta;
import com.otilm.api.model.core.acme.Identifier;
import com.otilm.api.model.core.acme.NewAccountRequest;
import com.otilm.api.model.core.acme.Order;
import com.otilm.api.model.core.acme.OrderStatus;
import com.otilm.api.model.core.acme.Problem;
import com.otilm.api.model.core.acme.ProblemDocument;
import com.otilm.api.model.core.authority.CertificateRevocationReason;
import com.otilm.api.model.core.certificate.CertificateChainResponseDto;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.certificate.request.ProtocolRequestAttributeValidator;
import com.otilm.core.certificate.request.RequestAttributePolicyViolationException;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.entity.acme.AcmeAccount;
import com.otilm.core.dao.entity.acme.AcmeAuthorization;
import com.otilm.core.dao.entity.acme.AcmeChallenge;
import com.otilm.core.dao.entity.acme.AcmeNonce;
import com.otilm.core.dao.entity.acme.AcmeOrder;
import com.otilm.core.dao.entity.acme.AcmeProfile;
import com.otilm.core.dao.repository.AcmeProfileRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.acme.AcmeAccountRepository;
import com.otilm.core.dao.repository.acme.AcmeAuthorizationRepository;
import com.otilm.core.dao.repository.acme.AcmeChallengeRepository;
import com.otilm.core.dao.repository.acme.AcmeNonceRepository;
import com.otilm.core.dao.repository.acme.AcmeOrderRepository;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.security.authz.ProtocolEndpoint;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.acme.AcmeChallengeStateMachine;
import com.otilm.core.service.acme.AcmeConstants;
import com.otilm.core.service.acme.AcmeDnsChallengeValidator;
import com.otilm.core.service.acme.AcmeExternalService;
import com.otilm.core.service.acme.ChallengeValidationResult;
import com.otilm.core.service.acme.eab.AcmeEabVerifier;
import com.otilm.core.service.acme.identifier.AcmeCsrIdentifiers;
import com.otilm.core.service.acme.identifier.AcmeIdentifierPolicy;
import com.otilm.core.service.acme.message.AcmeJwsRequest;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.service.writer.AcmeChallengeWriter;
import com.otilm.core.util.AcmeCommonHelper;
import com.otilm.core.util.AcmeJsonProcessor;
import com.otilm.core.util.AcmePublicKeyProcessor;
import com.otilm.core.util.AcmeRandomGeneratorAndValidator;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.CertificateRequestUtils;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.SerializationUtil;
import com.otilm.core.util.X509ObjectToString;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
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
import java.time.DateTimeException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
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
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@Service
public class AcmeServiceImpl implements AcmeExternalService {

    private static final Logger logger = LoggerFactory.getLogger(AcmeServiceImpl.class);

    private static final int MAX_LISTED_IDENTIFIERS = 5;

    /** Longer than any DNS name or address literal, so a well-formed identifier is never the one that gets cut. */
    private static final int MAX_LISTED_IDENTIFIER_LENGTH = 255;

    private AcmeNonceRepository acmeNonceRepository;
    private RaProfileRepository raProfileRepository;
    private AcmeProfileRepository acmeProfileRepository;
    private AcmeAccountRepository acmeAccountRepository;
    private AcmeOrderRepository acmeOrderRepository;
    private AcmeAuthorizationRepository acmeAuthorizationRepository;
    private AcmeChallengeRepository acmeChallengeRepository;
    private ClientOperationInternalService clientOperationService;
    private CertificateInternalService certificateService;
    private AcmeChallengeWriter acmeChallengeWriter;
    private AcmeEabVerifier acmeEabVerifier;
    private PlatformTransactionManager transactionManager;

    @PersistenceContext
    private EntityManager entityManager;

    private AttributeEngine attributeEngine;
    private ProtocolRequestAttributeValidator protocolRequestAttributeValidator;

    @Autowired
    public void setAcmeChallengeWriter(AcmeChallengeWriter acmeChallengeWriter) {
        this.acmeChallengeWriter = acmeChallengeWriter;
    }

    @Autowired
    public void setAcmeEabVerifier(AcmeEabVerifier acmeEabVerifier) {
        this.acmeEabVerifier = acmeEabVerifier;
    }

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.transactionManager = transactionManager;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setProtocolRequestAttributeValidator(
            ProtocolRequestAttributeValidator protocolRequestAttributeValidator) {
        this.protocolRequestAttributeValidator = protocolRequestAttributeValidator;
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
    public void setClientOperationService(ClientOperationInternalService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    @Override
    @ProtocolEndpoint
    @Transactional
    public ResponseEntity<Directory> getDirectory(String acmeProfileName, URI requestUri, boolean isRaProfileBased)
            throws AcmeProblemDocumentException {
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
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.SERVER_INTERNAL,
                    "Given profile name is not found");
        }
        logger.debug("Directory information retrieved: {}", directory);

        return ResponseEntity
                .ok()
                .cacheControl(CacheControl.noStore())
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .body(directory);
    }

    @Override
    @ProtocolEndpoint
    @Transactional
    public ResponseEntity<?> getNonce(String acmeProfileName, Boolean isHead, URI requestUri,
            boolean isRaProfileBased) {
        String nonce = generateNonce();
        logger.debug("New Nonce: {}", nonce);
        ResponseEntity.HeadersBuilder<?> responseBuilder;
        if (isHead) {
            responseBuilder = ResponseEntity.ok().cacheControl(CacheControl.noStore());
        } else {
            responseBuilder = ResponseEntity.noContent().cacheControl(CacheControl.noStore());
        }

        return responseBuilder
                .header(AcmeConstants.NONCE_HEADER_NAME, nonce)
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .build();
    }

    /**
     * Runs without an ambient transaction. Admitting an account takes a vault round-trip to read the binding key, and a
     * transaction opened before it would hold its connection for the whole of that — on an endpoint any client can
     * reach. Each read below therefore runs in its own short transaction, and the account is written in an explicit one
     * that re-reads the profile under a lock.
     *
     * <p>
     * This removes the connection this method would otherwise hold across the vault call. It does not remove the one
     * the secret read opens for itself: {@code SecretServiceImpl.getSecretContent} is transactional and writes a secret
     * version after the connector answers, so the call still runs inside a transaction of its own.
     */
    @Override
    @ProtocolEndpoint
    @org.springframework.transaction.annotation.Transactional(propagation = Propagation.NOT_SUPPORTED)
    public ResponseEntity<Account> newAccount(String acmeProfileName, String requestJson, URI requestUri,
            boolean isRaProfileBased) throws AcmeProblemDocumentException {
        if (requestJson.isEmpty()) {
            logger.error("New Account request is empty. JWS is malformed for profile: {}", acmeProfileName);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }

        // Parse and check the JWS request
        AcmeJwsRequest jwsRequest = new AcmeJwsRequest(requestJson);
        validateRequest(jwsRequest, acmeProfileName, requestUri, isRaProfileBased);

        NewAccountRequest accountRequest = AcmeJsonProcessor
                .getPayloadAsRequestObject(jwsRequest.getJwsObject(), NewAccountRequest.class);
        logger.debug("New Account request: {}", accountRequest.toString());

        boolean created = false;
        // Check if the Account already exists
        AcmeAccount account = acmeAccountRepository
                .findByPublicKey(AcmePublicKeyProcessor.publicKeyPemStringFromObject(jwsRequest.getPublicKey()));

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
                account = addNewAccount(acmeProfileName,
                        AcmePublicKeyProcessor.publicKeyPemStringFromObject(jwsRequest.getPublicKey()), accountRequest,
                        isRaProfileBased, jwsRequest.getJwk(), requestUri);
                created = account.getUuid() != null;
            }
        }

        // Only for an account that already existed: one just created was built from these very profiles, so the
        // check could only fail on a concurrent edit - and it runs after the row is committed, where refusing would
        // leave an account the client never learns the id of.
        if (!created) {
            checkAccountConfiguration(account, acmeProfileName, isRaProfileBased);
        }

        Account accountDto = account.mapToDto();
        String baseUri = getAcmeBaseUri();
        LoggingHelper
                .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, false,
                        account.getUuid().toString(), account.getAccountId());

        ResponseEntity.BodyBuilder responseBuilder;
        if (isRaProfileBased) {
            accountDto
                    .setOrders("%s/raProfile/%s/acct/%s/orders"
                            .formatted(baseUri, acmeProfileName, account.getAccountId()));
            if (accountRequest.isOnlyReturnExisting()) {
                responseBuilder = ResponseEntity
                        .ok()
                        .location(URI
                                .create("%s/raProfile/%s/acct/%s"
                                        .formatted(baseUri, acmeProfileName, account.getAccountId())));
            } else {
                responseBuilder = ResponseEntity
                        .created(URI
                                .create("%s/raProfile/%s/acct/%s"
                                        .formatted(baseUri, acmeProfileName, account.getAccountId())));
            }
        } else {
            accountDto.setOrders("%s/%s/acct/%s/orders".formatted(baseUri, acmeProfileName, account.getAccountId()));
            if (accountRequest.isOnlyReturnExisting()) {
                responseBuilder = ResponseEntity
                        .ok()
                        .location(URI
                                .create("%s/%s/acct/%s".formatted(baseUri, acmeProfileName, account.getAccountId())));
            } else {
                responseBuilder = ResponseEntity
                        .created(URI
                                .create("%s/%s/acct/%s".formatted(baseUri, acmeProfileName, account.getAccountId())));
            }
        }

        return responseBuilder
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.RETRY_HEADER_NAME, retryIntervalHeader(account))
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .body(accountDto);
    }

    @Override
    @ProtocolEndpoint
    @Transactional
    public ResponseEntity<Account> updateAccount(String acmeProfileName, String accountId, String requestJson,
            URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
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
            LoggingHelper
                    .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, false,
                            account.getUuid().toString(), account.getAccountId());
        } catch (NotFoundException e) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ACCOUNT_DOES_NOT_EXIST);
        }

        validateAccount(account);
        requireOwnership(jwsRequest, account);

        Account request = AcmeJsonProcessor.getPayloadAsRequestObject(jwsRequest.getJwsObject(), Account.class);
        logger.debug("Account Update request: {}", request.toString());
        boolean deactivate = request.getStatus() != null && request.getStatus().equals(AccountStatus.DEACTIVATED);
        // The orders are locked and settled before the account row is touched, so the account row is written only
        // after every order lock is held, in the order the other writers take them.
        if (deactivate) {
            logger.info("Deactivating Account with ID: {}", accountId);
            deactivateOrders(account);
        }
        if (request.getContact() != null) {
            account.setContact(SerializationUtil.serialize(request.getContact()));
        }
        if (deactivate) {
            account.setStatus(AccountStatus.DEACTIVATED);
        }
        acmeAccountRepository.save(account);
        if (logger.isDebugEnabled()) {
            logger.debug("Updated Account: {}", account.mapToDto().toString());
        }

        return ResponseEntity
                .ok()
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.RETRY_HEADER_NAME, retryIntervalHeader(account))
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .body(account.mapToDto());
    }

    @Override
    @ProtocolEndpoint
    @Transactional
    public ResponseEntity<?> keyRollover(String acmeProfileName, String requestJson, URI requestUri,
            boolean isRaProfileBased) throws AcmeProblemDocumentException {
        if (requestJson.isEmpty()) {
            logger.error("Update Account request is empty. JWS is malformed for profile: {}", acmeProfileName);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }

        // Parse and check the JWS request
        AcmeJwsRequest jwsRequest = new AcmeJwsRequest(requestJson);
        validateRequest(jwsRequest, acmeProfileName, requestUri, isRaProfileBased);

        AcmeJwsRequest innerJws = new AcmeJwsRequest(jwsRequest.getJsonStringPayload());
        validateKey(jwsRequest.getJwsObject(), innerJws.getJwsObject());
        validateRequestNoNonce(innerJws, acmeProfileName, requestUri, isRaProfileBased);
        KeyChange keyChange = AcmeJsonProcessor.getPayloadAsRequestObject(innerJws.getJwsObject(), KeyChange.class);
        if (keyChange.account() == null || keyChange.oldKey() == null) {
            throw AcmeJsonProcessor.malformedPayload();
        }

        PublicKey newKey = innerJws.getPublicKey();
        PublicKey oldKey = parseOldKey(keyChange.oldKey());

        String account = keyChange.account();
        String accountId = account.substring(account.lastIndexOf('/') + 1);

        AcmeAccount acmeAccount;
        try {
            acmeAccount = getAcmeAccountEntity(accountId);
            LoggingHelper
                    .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, false,
                            acmeAccount.getUuid().toString(), acmeAccount.getAccountId());
        } catch (NotFoundException e) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ACCOUNT_DOES_NOT_EXIST);
        }

        validateAccount(acmeAccount);
        requireOwnership(jwsRequest, acmeAccount);

        if (!acmeAccount.getPublicKey().equals(AcmePublicKeyProcessor.publicKeyPemStringFromObject(oldKey))) {
            logger.error("Public key of the Account with ID: {} does not match with old key in request", accountId);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.UNAUTHORIZED,
                    "Account key does not match with old key");
        }
        AcmeAccount oldAccount = acmeAccountRepository
                .findByPublicKey(AcmePublicKeyProcessor.publicKeyPemStringFromObject(newKey));
        if (oldAccount != null) {
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .header(AcmeConstants.LOCATION_HEADER_NAME, oldAccount.getAccountId())
                    .body(new ProblemDocument("keyExists", "New Key already exists",
                            "New key already tagged to a different account"));
        }

        acmeAccount.setPublicKey(AcmePublicKeyProcessor.publicKeyPemStringFromObject(newKey));
        acmeAccountRepository.save(acmeAccount);

        return ResponseEntity
                .ok()
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .build();
    }

    @Override
    @ProtocolEndpoint
    @Transactional
    public ResponseEntity<Order> newOrder(String acmeProfileName, String requestJson, URI requestUri,
            boolean isRaProfileBased) throws AcmeProblemDocumentException {
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
            LoggingHelper
                    .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, true,
                            acmeAccount.getUuid().toString(), acmeAccount.getAccountId());
            validateAccount(acmeAccount);
            logger.info("ACME Account set: {}", acmeAccount);
        } catch (NotFoundException e) {
            logger.error("Requested Account with ID {} does not exists", acmeAccountId);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ACCOUNT_DOES_NOT_EXIST);
        }

        AcmeOrder order = generateOrder(acmeAccount, jwsRequest);
        logger.debug("Order created: {}", order);
        LoggingHelper
                .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ORDER, false,
                        order.getUuid().toString(), order.getOrderId());

        return ResponseEntity
                .created(URI.create(order.getUrl()))
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.RETRY_HEADER_NAME, retryIntervalHeader(order.getAcmeAccount()))
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .body(order.mapToDto());
    }

    @Override
    @ProtocolEndpoint
    @Transactional
    public ResponseEntity<List<Order>> listOrders(String acmeProfileName, String accountId, URI requestUri,
            boolean isRaProfileBased) throws AcmeProblemDocumentException {
        AcmeAccount acmeAccount;
        try {
            acmeAccount = getAcmeAccountEntity(accountId);
            LoggingHelper
                    .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, true,
                            acmeAccount.getUuid().toString(), acmeAccount.getAccountId());
        } catch (NotFoundException e) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ACCOUNT_DOES_NOT_EXIST);
        }

        Integer invalidatedOrders = acmeOrderRepository.invalidateExpiredOrders(acmeAccount, new Date());
        acmeAccount.setFailedOrders(acmeAccount.getFailedOrders() + invalidatedOrders);
        acmeAccountRepository.save(acmeAccount);

        logger.debug("Request to list Orders for the Account with ID: {}", accountId);
        List<Order> orders = acmeAccount.getOrders().stream().map(AcmeOrder::mapToDto).collect(Collectors.toList());
        logger.debug("Number of Orders: {}", orders.size());

        return ResponseEntity
                .ok()
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .body(orders);
    }

    @Override
    @ProtocolEndpoint
    @Transactional
    public ResponseEntity<Authorization> getAuthorization(String acmeProfileName, String authorizationId,
            String requestJson, URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        if (requestJson.isEmpty()) {
            logger.error("Update Account request is empty. JWS is malformed for profile: {}", acmeProfileName);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }

        // Parse and check the JWS request
        AcmeJwsRequest jwsRequest = new AcmeJwsRequest(requestJson);
        validateRequest(jwsRequest, acmeProfileName, requestUri, isRaProfileBased);
        boolean isDeactivateRequest = isDeactivationRequest(jwsRequest);
        AcmeAuthorization authorization = loadAuthorization(authorizationId);
        requireOwnership(jwsRequest, authorization.getOrder().getAcmeAccount());
        LoggingHelper
                .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_AUTHORIZATION, false,
                        authorization.getUuid().toString(), authorization.getAuthorizationId());
        LoggingHelper
                .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ORDER, true,
                        authorization.getOrder().getUuid().toString(), authorization.getOrder().getOrderId());
        settleStaleStatuses(authorization.getOrder());
        rejectExpiredAuthorization(authorization);

        if (isDeactivateRequest) {
            authorization = acmeChallengeWriter
                    .deactivateAuthorization(authorization.getOrder().getUuid(), authorizationId);
        }

        Authorization authorizationDto = authorization.mapToDto();
        logger.debug("Authorization: {}", authorizationDto.toString());

        return ResponseEntity
                .ok()
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .body(authorizationDto);
    }

    @Override
    @ProtocolEndpoint
    // Spring's annotation rather than the class's jakarta one: the transaction-boundary rules read Spring's, and the
    // rollback attribute is what those rules require of a method declaring a checked exception.
    @org.springframework.transaction.annotation.Transactional(propagation = Propagation.NOT_SUPPORTED,
            noRollbackFor = AcmeProblemDocumentException.class)
    public ResponseEntity<Challenge> validateChallenge(String acmeProfileName, String challengeId, URI requestUri,
            boolean isRaProfileBased) throws AcmeProblemDocumentException {
        logger.debug("Validating Challenge with ID {}:", challengeId);
        AcmeChallenge challenge = loadChallenge(challengeId);
        AcmeOrder order = challenge.getAuthorization().getOrder();
        validateAccount(order.getAcmeAccount());
        logger.debug("Authorization corresponding to the Order: {}", challenge.getAuthorization().toString());
        logger.debug("Order corresponding to the Challenge: {}", order.toString());
        LoggingHelper
                .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ORDER, true, order.getUuid().toString(),
                        order.getOrderId());

        if (AcmeChallengeStateMachine.hasStaleStatus(order)) {
            acmeChallengeWriter.settleOrder(order.getUuid());
            challenge = loadChallenge(challengeId);
        }
        AcmeAuthorization authorization = challenge.getAuthorization();
        rejectExpiredAuthorization(authorization, "Challenge is expired");

        if (challenge.getStatus() != ChallengeStatus.PENDING
                || authorization.getStatus() != AuthorizationStatus.PENDING) {
            logger
                    .debug("Challenge {} is {} on a {} authorization, returning its current state without validating",
                            challengeId, challenge.getStatus(), authorization.getStatus());
            return challengeResponse(acmeProfileName, challenge, isRaProfileBased);
        }

        ChallengeValidationResult result = challenge.getType().equals(ChallengeType.HTTP01)
                ? validateHttpChallenge(challenge)
                : validateDnsChallenge(challenge);
        AcmeChallenge settledChallenge = acmeChallengeWriter
                .applyValidationResult(order.getUuid(), challengeId, result);
        logger.debug("Validation of the Challenge is completed: {}", settledChallenge);

        return challengeResponse(acmeProfileName, settledChallenge, isRaProfileBased);
    }

    /**
     * Settles the rows of an order that an instance not yet propagating challenge failures left stale, before the order
     * or one of its authorizations is judged or answered.
     */
    private void settleStaleStatuses(AcmeOrder order) {
        if (AcmeChallengeStateMachine.hasStaleStatus(order)) {
            acmeChallengeWriter.settleOrder(order.getUuid());
        }
    }

    private ResponseEntity<Challenge> challengeResponse(String acmeProfileName, AcmeChallenge challenge,
            boolean isRaProfileBased) {
        return ResponseEntity
                .ok()
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .header(AcmeConstants.LINK_HEADER_NAME, "<" + challenge.getAuthorization().getUrl() + ">;rel=\"up\"")
                .body(challenge.mapToDto());
    }

    /**
     * Runs without a transaction, which is why the class declares none. One held across the submission keeps the
     * request's connection idle in transaction for all of it while the submission works on a second connection. Not
     * {@code NOT_SUPPORTED} either: once the request has read outside a transaction, the transactions started under it
     * run on EntityManagers of their own, so the order {@code validateOrder} reconciles would come back detached. The
     * order is written only under its lock: claimed for processing before the submission, so a second finalize request
     * submits nothing, and updated after it from its current state, which an account deactivation may have changed.
     */
    @Override
    @ProtocolEndpoint
    public ResponseEntity<Order> finalizeOrder(String acmeProfileName, String orderId, String requestJson,
            URI requestUri, boolean isRaProfileBased) throws AcmeProblemDocumentException {
        if (requestJson.isEmpty()) {
            logger.error("Update Account request is empty. JWS is malformed for profile: {}", acmeProfileName);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }

        // Parse and check the JWS request
        AcmeJwsRequest jwsRequest = new AcmeJwsRequest(requestJson);
        validateRequest(jwsRequest, acmeProfileName, requestUri, isRaProfileBased);
        CertificateFinalizeRequest request = AcmeJsonProcessor
                .getPayloadAsRequestObject(jwsRequest.getJwsObject(), CertificateFinalizeRequest.class);
        logger.debug("Finalize Order request: {}", request);
        byte[] csr = decodeBase64Url(request.getCsr(), "CSR");

        logger.debug("Request to finalize the Order with ID: {}", orderId);
        AcmeOrder order = validateOrder(orderId);
        LoggingHelper
                .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ORDER, false,
                        order.getUuid().toString(), order.getOrderId());
        if (order.getAcmeAccount() != null) {
            LoggingHelper
                    .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, true,
                            order.getAcmeAccount().getUuid().toString(), order.getAcmeAccount().getAccountId());
        }

        validateAccount(order.getAcmeAccount());
        requireOwnership(jwsRequest, order.getAcmeAccount());
        logger.debug("Order found : {}", order);

        if (!order.getStatus().equals(OrderStatus.READY)) { // A request to finalize an order will result in error if
                                                            // the order is not in the "ready" state
            logger.error("Cannot finalize Order that is not ready.");
            throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.ORDER_NOT_READY);
        }

        AcmeOrder finalized = finalizeOrder(order, csr, isRaProfileBased);

        return ResponseEntity
                .ok()
                .location(URI.create(finalized.getUrl()))
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.RETRY_HEADER_NAME, retryIntervalHeader(finalized.getAcmeAccount()))
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .body(finalized.mapToDto());
    }

    private AcmeOrder finalizeOrder(AcmeOrder order, byte[] csr, boolean isRaProfileBased)
            throws AcmeProblemDocumentException {
        logger.debug("Finalizing Order with ID: {}", order.getOrderId());
        JcaPKCS10CertificationRequest p10Object;
        String decodedCsr;
        try {
            p10Object = new JcaPKCS10CertificationRequest(csr);
            validateCSR(p10Object, order);
            decodedCsr = CertificateRequestUtils.normalizeCsrContent(JcaPKCS10CertificationRequestToString(p10Object));
        } catch (IOException e) {
            logger.error(e.getMessage());
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_CSR);
        }

        logger.debug("Initiating issue Certificate for Order with ID: {}", order.getOrderId());
        ClientCertificateIssueRequestDto certificateIssueRequestDto = new ClientCertificateIssueRequestDto();
        certificateIssueRequestDto
                .setAttributes(getClientOperationAttributes(false, order.getAcmeAccount(), isRaProfileBased));
        certificateIssueRequestDto.setRequest(decodedCsr);
        certificateIssueRequestDto.setFormat(CertificateRequestFormat.PKCS10);
        if (!acmeChallengeWriter.claimForFinalize(order.getUuid())) {
            logger.debug("Order {} was finalized by another request meanwhile", order.getOrderId());
            throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.ORDER_NOT_READY);
        }
        return createCert(order, certificateIssueRequestDto);
    }

    @Override
    @ProtocolEndpoint
    @Transactional
    public ResponseEntity<Order> getOrder(String acmeProfileName, String orderId, URI requestUri,
            boolean isRaProfileBased) throws AcmeProblemDocumentException {
        AcmeOrder order = validateOrder(orderId);
        LoggingHelper
                .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ORDER, false,
                        order.getUuid().toString(), order.getOrderId());
        if (order.getAcmeAccount() != null) {
            LoggingHelper
                    .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ACCOUNT, true,
                            order.getAcmeAccount().getUuid().toString(), order.getAcmeAccount().getAccountId());
        }

        // An invalid order is a state the protocol defines, not a server fault: it is returned with that status
        // (RFC 8555 section 7.1.3). Why validation failed is reported per identifier, on the challenges of the
        // order's authorizations.
        if (order.getStatus().equals(OrderStatus.INVALID)) {
            logger.debug("Order {} is invalid", order.getOrderId());
        }

        return ResponseEntity
                .ok()
                .location(URI.create(order.getUrl()))
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.RETRY_HEADER_NAME, retryIntervalHeader(order.getAcmeAccount()))
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .body(order.mapToDto());
    }

    @Override
    @ProtocolEndpoint
    @Transactional
    public ResponseEntity<Resource> downloadCertificate(String acmeProfileName, String certificateId, URI requestUri,
            boolean isRaProfileBased) throws NotFoundException, CertificateException {
        logger.debug("Downloading the Certificate with ID: {}", certificateId);
        ByteArrayResource byteArrayResource = getCertificateResource(certificateId);

        return ResponseEntity
                .ok()
                .header(AcmeConstants.NONCE_HEADER_NAME, generateNonce())
                .header(AcmeConstants.LINK_HEADER_NAME, generateLinkHeader(acmeProfileName, isRaProfileBased))
                .contentType(MediaType.valueOf("application/pem-certificate-chain"))
                .body(byteArrayResource);
    }

    @Override
    @ProtocolEndpoint
    @Transactional
    public ResponseEntity<?> revokeCertificate(String acmeProfileName, String requestJson, URI requestUri,
            boolean isRaProfileBased) throws AcmeProblemDocumentException, ConnectorException, CertificateException {
        if (requestJson.isEmpty()) {
            logger.error("Update Account request is empty. JWS is malformed for profile: {}", acmeProfileName);
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED);
        }

        // Parse and check the JWS request
        AcmeJwsRequest jwsRequest = new AcmeJwsRequest(requestJson);
        validateRequest(jwsRequest, acmeProfileName, requestUri, isRaProfileBased);

        CertificateRevocationRequest request = AcmeJsonProcessor
                .getPayloadAsRequestObject(jwsRequest.getJwsObject(), CertificateRevocationRequest.class);
        byte[] certificateDer = decodeBase64Url(request.getCertificate(), "Certificate to revoke");
        logger.debug("Certificate revocation is triggered with the payload: {}", request.toString());

        ClientCertificateRevocationDto revokeRequest = new ClientCertificateRevocationDto();

        Certificate cert = loadCertificateToRevoke(certificateDer);
        LoggingHelper
                .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.CERTIFICATE, false,
                        cert.getUuid().toString(), X509CertificateEntity.subjectDnOrNull(cert));
        if (cert.isArchived()) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ARCHIVED);
        }
        if (cert.getState().equals(CertificateState.REVOKED)) {
            logger
                    .error("Certificate is already revoked. Serial number: {}, Fingerprint: {}", cert.getSerialNumber(),
                            cert.getFingerprint());
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ALREADY_REVOKED);
        }

        if (jwsRequest.isJwkPresent()) { // signed with the key pair of the certificate
            logger.debug("Validating revocation request signed with the key pair of the certificate");
            PublicKey certPublicKey = CertificateUtil.getX509Certificate(certificateDer).getPublicKey();
            PublicKey jwsPublicKey = jwsRequest.getPublicKey();

            String pemPubKeyCert = AcmePublicKeyProcessor.publicKeyPemStringFromObject(certPublicKey);
            String pemPubKeyJws = AcmePublicKeyProcessor.publicKeyPemStringFromObject(jwsPublicKey);
            if (!pemPubKeyCert.equals(pemPubKeyJws)) { // check that the public key of the certificate matches the
                                                       // public key of the JWS
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_PUBLIC_KEY);
            }
        }

        AcmeAccount acmeAccount = null;
        if (jwsRequest.isKidPresent()) { // signed with the account key pair
            logger.debug("Validating revocation request signed with the account key pair");
            // check that the associated protocol is ACME
            if (cert.getProtocolAssociation() == null) {
                throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.UNAUTHORIZED,
                        "Certificate is not associated with protocol");
            } else if (cert.getProtocolAssociation().getProtocol() != CertificateProtocol.ACME) {
                throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.UNAUTHORIZED,
                        "Certificate is not associated with ACME protocol");
            }
            // check that the ACME account ID of the certificate matches the account ID in the request
            acmeAccount = acmeAccountRepository
                    .findByUuid(cert.getProtocolAssociation().getAdditionalProtocolUuid())
                    .orElseThrow(() -> new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.UNAUTHORIZED,
                            "Unable to find the ACME account that is associated with the certificate"));
            String kid = jwsRequest.getKid();
            String requestAccountId = kid.split("/")[kid.split("/").length - 1];
            if (!acmeAccount.getAccountId().equals(requestAccountId)) {
                throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.UNAUTHORIZED,
                        "Account does not match the certificate associated ACME Account");
            }
        }

        // if the revocation reason is null, set it to UNSPECIFIED, otherwise get the code from the request
        final CertificateRevocationReason reason = request.getReason() == null
                ? CertificateRevocationReason.UNSPECIFIED
                : CertificateRevocationReason.fromReasonCode(request.getReason());
        // when the reason is null, it means, that is not in the list
        if (reason == null) {
            final String details = "Allowed revocation reason codes are: " + Arrays
                    .toString(Arrays
                            .stream(CertificateRevocationReason.values())
                            .map(CertificateRevocationReason::getCode)
                            .toArray());
            throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.BAD_REVOCATION_REASON, details);
        }

        revokeRequest.setReason(reason);
        revokeRequest.setAttributes(getClientOperationAttributes(true, acmeAccount, isRaProfileBased));

        try {
            clientOperationService
                    .revokeCertificate(
                            SecuredParentUUID.fromUUID(cert.getRaProfile().getAuthorityInstanceReferenceUuid()),
                            cert.getRaProfile().getSecuredUuid(), cert.getUuid().toString(), revokeRequest);
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
        return ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
                + AcmeConstants.ACME_URI_HEADER;
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
        meta.setExternalAccountRequired(acmeProfile.isExternalAccountRequired());
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

    private AcmeAccount addNewAccount(String profileName, String publicKey, NewAccountRequest accountRequest,
            boolean isRaProfileBased, JWK accountKey, URI requestUri) throws AcmeProblemDocumentException {
        AcmeRaProfiles acmeRaProfiles = getProfiles(profileName, isRaProfileBased);
        AcmeProfile acmeProfile = acmeRaProfiles.acmeProfile;
        RaProfile raProfileToUse = acmeRaProfiles.raProfile;

        if (logger.isDebugEnabled()) {
            logger
                    .debug("RA Profile for new Account: {}, ACME Profile: {}", raProfileToUse.toString(),
                            acmeProfile.toString());
        }
        String accountId = AcmeRandomGeneratorAndValidator.generateRandomId();
        AcmeAccount oldAccount = acmeAccountRepository.findByPublicKey(publicKey);
        if (acmeProfile.isRequireContact() != null && acmeProfile.isRequireContact()
                && (accountRequest.getContact() == null || accountRequest.getContact().isEmpty())) {
            logger.error("Contact not found for Account: {}", accountRequest);
            {
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.INVALID_CONTACT,
                        "Contact information is missing in the Request. It is set as mandatory for this profile");
            }
        }

        // Clients agree to terms only when the directory advertises them, so the requirement binds only with a URL.
        if (acmeProfile.isRequireTermsOfService() != null && acmeProfile.isRequireTermsOfService()
                && acmeProfile.getTermsOfServiceUrl() != null && !acmeProfile.getTermsOfServiceUrl().isBlank()
                && !accountRequest.isTermsOfServiceAgreed()) {
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
        // The binding is the account's admission: verified before any row exists, so a rejected one leaves
        // nothing behind. Reading its key goes to the vault, which is why no transaction is open here.
        UUID eabSecretUuid = acmeProfile.isExternalAccountRequired()
                ? acmeEabVerifier
                        .verify(acmeProfile, accountRequest.getExternalAccountBinding(), accountKey, requestUri)
                : null;
        AcmeAccount account = new AcmeAccount();
        account.setEabSecretUuid(eabSecretUuid);
        account.setAcmeProfile(acmeProfile);
        account.setEnabled(true);
        account.setStatus(AccountStatus.VALID);
        account.setTermsOfServiceAgreed(true);
        account.setRaProfile(raProfileToUse);
        account.setPublicKey(publicKey);
        account.setDefaultRaProfile(!isRaProfileBased);
        account.setAccountId(accountId);
        account
                .setContact(SerializationUtil
                        .serialize(accountRequest.getContact() != null ? accountRequest.getContact() : List.of()));
        insertAccountAgainstTheProfileAsItStands(account, acmeProfile, eabSecretUuid);
        logger.debug("ACME Account created: {}", account);
        return account;
    }

    /**
     * Writes the account in its own transaction, having re-read the profile under a row lock. The profile the binding
     * was verified against was read before the vault round-trip, and an edit in that window could have turned the
     * requirement on, or withdrawn the very key that verified. Deciding again here, on the locked row, is what keeps
     * the admission and the profile consistent.
     */
    private void insertAccountAgainstTheProfileAsItStands(AcmeAccount account, AcmeProfile acmeProfile,
            UUID eabSecretUuid) throws AcmeProblemDocumentException {
        TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
        try {
            // Detached first: with open-in-view the copy read before the vault call is still managed, and a locked
            // read would hand back that same instance with its pre-vault state rather than what the row now holds.
            entityManager.detach(acmeProfile);
            AcmeProfile locked = acmeProfileRepository
                    .findAndLockByUuid(acmeProfile.getUuid())
                    .orElseThrow(() -> new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                            "The ACME Profile no longer exists"));
            requireBindingStillAccepted(locked, eabSecretUuid);
            acmeAccountRepository.save(account);
            transactionManager.commit(transaction);
        } catch (RuntimeException | AcmeProblemDocumentException e) {
            throw e;
        } finally {
            // Not in the catch: a failure inside commit() has already rolled back and completed the transaction,
            // and rolling back again would replace the real cause with an IllegalTransactionStateException.
            if (!transaction.isCompleted()) {
                transactionManager.rollback(transaction);
            }
        }
    }

    /**
     * The retry hint, defaulted when the profile carries none. An edit that omits the interval stores null, and a
     * response is written after its changes are committed: throwing here would answer 500 for work already done.
     */
    private static String retryIntervalHeader(AcmeAccount account) {
        Integer retryInterval = account.getAcmeProfile().getRetryInterval();
        return String.valueOf(retryInterval == null ? AcmeConstants.DEFAULT_RETRY_INTERVAL : retryInterval);
    }

    /**
     * How long an order and its authorizations stay valid, in seconds: the profile's validity, or the documented
     * default when the profile sets none, as an edit that omits it leaves it.
     */
    private static int orderValidity(AcmeProfile profile) {
        Integer validity = profile.getValidity();
        return validity == null ? AcmeConstants.DEFAULT_ORDER_VALIDITY : validity;
    }

    /** The profile as the locked row has it, not as it was when the binding was verified. */
    private void requireBindingStillAccepted(AcmeProfile locked, UUID eabSecretUuid)
            throws AcmeProblemDocumentException {
        if (!locked.isExternalAccountRequired()) {
            return;
        }
        if (eabSecretUuid == null) {
            // The requirement was switched on mid-request. The client sent no binding and is not being turned down
            // for a bad one, so it gets the answer that tells it to bring one.
            logger
                    .info("ACME profile '{}': External Account Binding became required while the account was being "
                            + "created", locked.getName());
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.EXTERNAL_ACCOUNT_REQUIRED);
        }
        if (!locked.getEabSecretUuids().contains(eabSecretUuid)) {
            logger
                    .info("ACME profile '{}': External Account Binding rejected - the key was withdrawn while the "
                            + "binding was being verified", locked.getName());
            throw new AcmeProblemDocumentException(HttpStatus.UNAUTHORIZED, Problem.UNAUTHORIZED,
                    AcmeEabVerifier.REJECTION);
        }
    }

    private RaProfile getRaProfileEntity(String name) throws NotFoundException {
        return raProfileRepository.findByName(name).orElseThrow(() -> new NotFoundException(RaProfile.class, name));
    }

    private AcmeProfile getAcmeProfileEntityByName(String name) throws NotFoundException {
        return acmeProfileRepository.findByName(name).orElseThrow(() -> new NotFoundException(AcmeProfile.class, name));
    }

    private AcmeAccount getAcmeAccountEntity(String accountId) throws NotFoundException {
        return acmeAccountRepository
                .findByAccountId(accountId)
                .orElseThrow(() -> new NotFoundException(AcmeAccount.class, accountId));
    }

    private void validateAccount(AcmeAccount acmeAccount) throws AcmeProblemDocumentException {
        if (!acmeAccount.getStatus().equals(AccountStatus.VALID)) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.UNAUTHORIZED,
                    "The requested account has been deactivated");
        }
    }

    private void deactivateOrders(AcmeAccount acmeAccount) {
        int closed = 0;
        // The orders are taken in a fixed order. Each lock is held until this request commits, so two
        // deactivations of one account walking them in different orders would each hold the order the other
        // waits for.
        List<AcmeOrder> orders = acmeAccount
                .getOrders()
                .stream()
                .sorted(Comparator.comparing(AcmeOrder::getUuid))
                .toList();
        for (AcmeOrder order : orders) {
            if (acmeChallengeWriter.deactivateOrder(order.getUuid())) {
                closed++;
            }
        }
        // The account is written once, after every order has been locked: writing it earlier would make a
        // validation holding a later order wait for the account while this request waits for that order. It is
        // then re-read so that writing it back afterwards carries this count rather than the one loaded before.
        acmeChallengeWriter.countFailedOrders(acmeAccount.getUuid(), closed);
        entityManager.refresh(acmeAccount);
    }

    private void validateKey(JWSObject jwsRequestObject, JWSObject jwsInnerObject) throws AcmeProblemDocumentException {
        if (!jwsInnerObject.getHeader().toJSONObject().containsKey("jwk")) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "Inner JWS does not contain jwk");
        }
        if (!Objects
                .equals(jwsInnerObject.getHeader().toJSONObject().getOrDefault("url", "innerUrl"),
                        jwsRequestObject.getHeader().toJSONObject().getOrDefault("url", "outerUrl"))) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "URL in inner and outer JWS are different");
        }
        if (jwsInnerObject.getHeader().toJSONObject().containsKey("nonce")) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "Inner JWS cannot contain nonce header");
        }
    }

    private AcmeOrder generateOrder(AcmeAccount acmeAccount, AcmeJwsRequest jwsRequest)
            throws AcmeProblemDocumentException {
        logger.debug("Generating new Order for Account: {}", acmeAccount.toString());
        Order orderRequest = AcmeJsonProcessor.getPayloadAsRequestObject(jwsRequest.getJwsObject(), Order.class);
        logger.debug("Order requested: {}", orderRequest.toString());
        AcmeProfile acmeProfile = acmeAccount.getAcmeProfile();
        List<Identifier> identifiers = requireIdentifiers(orderRequest);
        // Decided before the first row is written, so an order the profile refuses leaves nothing behind.
        Set<Identifier> preauthorized = resolvePreauthorized(acmeProfile, identifiers);
        AcmeOrder order = new AcmeOrder();
        order.setAcmeAccount(acmeAccount);
        order.setOrderId(AcmeRandomGeneratorAndValidator.generateRandomId());
        order.setStatus(OrderStatus.PENDING);
        order.setNotAfter(readOrderTimestamp(orderRequest.getNotAfter(), "notAfter"));
        order.setNotBefore(readOrderTimestamp(orderRequest.getNotBefore(), "notBefore"));
        order.setIdentifiers(SerializationUtil.serializeIdentifiers(identifiers));
        order.setExpires(AcmeCommonHelper.addSeconds(new Date(), orderValidity(acmeAccount.getAcmeProfile())));
        acmeOrderRepository.save(order);
        logger.debug("Order created: {}", order);

        Set<AcmeAuthorization> authorizations = generateValidations(order, identifiers, preauthorized);
        order.setAuthorizations(authorizations);
        AcmeChallengeStateMachine.readyWhenEveryAuthorizationIsValid(order);
        logger.debug("Challenges created for Order: {}", order);
        return order;
    }

    /**
     * The ordered identifiers, or a malformed problem. RFC 8555 section 7.4 requires the member, and every step below
     * assumes at least one identifier to authorize.
     */
    private static List<Identifier> requireIdentifiers(Order orderRequest) throws AcmeProblemDocumentException {
        List<Identifier> identifiers = orderRequest.getIdentifiers();
        if (identifiers == null || identifiers.isEmpty()) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "The order must name at least one identifier");
        }
        if (identifiers.stream().anyMatch(id -> id == null || id.getType() == null || id.getValue() == null)) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "Every identifier must have a type and a value");
        }
        return identifiers;
    }

    /**
     * A timestamp the order requests (RFC 8555 section 7.4), or null when the member is absent. A value that is not a
     * supported RFC 3339 timestamp from 1970 to 9999 is refused as malformed.
     */
    private static Date readOrderTimestamp(String value, String member) throws AcmeProblemDocumentException {
        try {
            return AcmeCommonHelper.getDateFromString(value);
        } catch (DateTimeException e) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    member + " is not a supported RFC 3339 timestamp from 1970 to 9999");
        }
    }

    /**
     * Which of the ordered identifiers the profile pre-authorizes. Under PREAUTHORIZED_ONLY the rest are refused, so
     * the whole order is decided here rather than identifier by identifier as rows are written.
     */
    private Set<Identifier> resolvePreauthorized(AcmeProfile acmeProfile, List<Identifier> identifiers)
            throws AcmeProblemDocumentException {
        Set<Identifier> preauthorized = Collections.newSetFromMap(new IdentityHashMap<>());
        List<String> uncovered = new ArrayList<>();
        for (Identifier identifier : identifiers) {
            if (!AcmeIdentifierPolicy.isSupportedType(identifier)) {
                // Nothing downstream knows how to prove control of a type the platform does not model, and an
                // authorization it can never validate would sit pending until the order expired.
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.UNSUPPORTED_IDENTIFIER,
                        "The order names an identifier of a type this server does not issue for");
            }
            if (AcmeIdentifierPolicy.covers(acmeProfile.preauthorizedIdentifierList(), identifier)) {
                preauthorized.add(identifier);
            } else {
                uncovered.add(identifier.getValue());
            }
        }
        if (!uncovered.isEmpty() && acmeProfile
                .effectiveIdentifierAuthorizationMode() == AcmeIdentifierAuthorizationMode.PREAUTHORIZED_ONLY) {
            String refused = summarize(uncovered);
            logger
                    .info("ACME profile '{}': order refused, identifiers not pre-authorized: {}", acmeProfile.getName(),
                            refused);
            throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.REJECTED_IDENTIFIER,
                    "The profile issues only for pre-authorized identifiers, and does not pre-authorize: " + refused);
        }
        return preauthorized;
    }

    /**
     * The refused identifiers as one bounded line. An order names as many identifiers as its body holds and each as
     * long as it likes, so listing them all would let one request size both the problem document and the log entry. A
     * few truncated values say which entry the policy is missing without handing the caller that choice.
     */
    private static String summarize(List<String> values) {
        String listed = values
                .stream()
                .limit(MAX_LISTED_IDENTIFIERS)
                .map(AcmeServiceImpl::singleLine)
                .map(AcmeServiceImpl::truncate)
                .collect(Collectors.joining(", "));
        int remaining = values.size() - MAX_LISTED_IDENTIFIERS;
        return remaining > 0 ? listed + " (and " + remaining + " more)" : listed;
    }

    private static String truncate(String value) {
        return value.length() <= MAX_LISTED_IDENTIFIER_LENGTH
                ? value
                : value.substring(0, MAX_LISTED_IDENTIFIER_LENGTH) + "...";
    }

    /**
     * Line separators removed: the value is the caller's, and a log line it can split is a log line it can forge. The
     * problem document needs this too, not only the log statement, because the exception advice logs the document.
     */
    private static String singleLine(String value) {
        return value == null ? "" : value.replaceAll("[\\r\\n\\u000B\\f\\u0085\\u2028\\u2029]", " ");
    }

    private Set<AcmeAuthorization> generateValidations(AcmeOrder acmeOrder, List<Identifier> identifiers,
            Set<Identifier> preauthorized) {
        Set<AcmeAuthorization> authorizations = new HashSet<>();
        for (Identifier identifier : identifiers) {
            authorizations.add(authorization(acmeOrder, identifier, preauthorized.contains(identifier)));
        }
        return authorizations;
    }

    private AcmeAuthorization authorization(AcmeOrder acmeOrder, Identifier identifier, boolean preauthorized) {
        AcmeAuthorization authorization = new AcmeAuthorization();
        authorization.setAuthorizationId(AcmeRandomGeneratorAndValidator.generateRandomId());
        authorization.setStatus(preauthorized ? AuthorizationStatus.VALID : AuthorizationStatus.PENDING);
        authorization.setOrder(acmeOrder);
        authorization
                .setExpires(AcmeCommonHelper
                        .addSeconds(new Date(), orderValidity(acmeOrder.getAcmeAccount().getAcmeProfile())));
        authorization.setWildcard(checkWildcard(identifier));
        authorization.setIdentifier(SerializationUtil.serialize(identifier));
        acmeAuthorizationRepository.save(authorization);
        if (preauthorized) {
            // Nothing is left to prove, and RFC 8555 section 7.1.4 gives a valid authorization no challenge to
            // respond to, so the client goes straight to finalize.
            authorization.setChallenges(Set.of());
            return authorization;
        }
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

    private ChallengeValidationResult validateHttpChallenge(AcmeChallenge challenge)
            throws AcmeProblemDocumentException {
        logger.debug("Initiating HTTP-01 Challenge validation: {}", challenge.toString());
        String identifierValue = identifierValue(challenge);
        String response = getHttpChallengeResponse(identifierValue.replace("*.", ""), challenge.getToken());
        PublicKey pubKey;
        try {
            pubKey = AcmePublicKeyProcessor
                    .publicKeyObjectFromString(challenge.getAuthorization().getOrder().getAcmeAccount().getPublicKey());
        } catch (Exception e) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.SERVER_INTERNAL);
        }
        String expectedResponse = AcmeCommonHelper.createKeyAuthorization(challenge.getToken(), pubKey);
        logger
                .debug("HTTP01 validation response from the server: {}, expected response: {}", response,
                        expectedResponse);
        if (!response.equals(expectedResponse)) {
            return ChallengeValidationResult
                    .failure(Problem.INCORRECT_RESPONSE, "The response served for the HTTP-01 challenge of "
                            + identifierValue + " does not match the expected key authorization");
        }
        return ChallengeValidationResult.success();
    }

    private ChallengeValidationResult validateDnsChallenge(AcmeChallenge challenge)
            throws AcmeProblemDocumentException {
        logger.info("Initiating DNS-01 validation for challenge: {}", challenge.toString());
        AcmeProfile acmeProfile = challenge.getAuthorization().getOrder().getAcmeAccount().getAcmeProfile();
        String expectedKeyAuthorization = generateDnsValidationToken(
                challenge.getAuthorization().getOrder().getAcmeAccount().getPublicKey(), challenge.getToken());
        return AcmeDnsChallengeValidator
                .validate(AcmeDnsChallengeValidator.challengeRecordName(identifierValue(challenge)),
                        expectedKeyAuthorization, AcmeDnsChallengeValidator
                                .resolverEnv(acmeProfile.getDnsResolverIp(), acmeProfile.getDnsResolverPort()));
    }

    private static String identifierValue(AcmeChallenge challenge) throws AcmeProblemDocumentException {
        Identifier identifier = SerializationUtil.deserializeIdentifier(challenge.getAuthorization().getIdentifier());
        if (identifier == null) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.SERVER_INTERNAL,
                    "Authorization has no identifier");
        }
        return identifier.getValue();
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
                    throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.TLS,
                            "Only 80 and 443 ports can be followed");
                }
                connection = (HttpURLConnection) new URL(finalUrl).openConnection();
                connection.setInstanceFollowRedirects(false);
                connection.setUseCaches(false);
                connection.setRequestMethod(AcmeConstants.HTTP_CHALLENGE_REQUEST_METHOD);
                connection.connect();
                int responseCode = connection.getResponseCode();
                if (100 <= connection.getResponseCode() && connection.getResponseCode() <= 399) {
                    BufferedReader bufferedReader = new BufferedReader(
                            new InputStreamReader(connection.getInputStream()));
                    acmeChallengeOutput = bufferedReader.lines().collect(Collectors.joining());
                }
                if (responseCode >= 300 && responseCode < 400) {
                    String redirectedUrl = connection.getHeaderField(AcmeConstants.LOCATION_HEADER_NAME);
                    if (null == redirectedUrl) {
                        break;
                    }
                    finalUrl = redirectedUrl;
                } else {
                    break;
                }
            } while (connection.getResponseCode() != HttpURLConnection.HTTP_OK
                    && redirectFollowCount < AcmeConstants.MAX_REDIRECT_COUNT);
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
            final byte[] encodedHashOfExpectedKeyAuthorization = digest
                    .digest(AcmeCommonHelper.createKeyAuthorization(token, pubKey).getBytes(StandardCharsets.UTF_8));
            return Base64URL.encode(encodedHashOfExpectedKeyAuthorization).toString();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error(e.getMessage());
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.SERVER_INTERNAL);
        }
    }

    private void validateCSR(JcaPKCS10CertificationRequest csr, AcmeOrder order) throws AcmeProblemDocumentException {
        AcmeCsrIdentifiers offered = AcmeCsrIdentifiers.of(csr);
        for (Identifier identifier : SerializationUtil.deserializeIdentifiers(order.getIdentifiers())) {
            if (!offered.carries(identifier)) {
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_CSR);
            }
        }

        try {
            CertificateRequest parsed = new Pkcs10CertificateRequest(csr.getEncoded());
            RaProfile raProfile = order.getAcmeAccount().getRaProfile();
            protocolRequestAttributeValidator.validate(parsed, raProfile);
        } catch (RequestAttributePolicyViolationException e) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_CSR, e.getMessage());
        } catch (CertificateException e) {
            // Availability failure resolving the request-attribute set: server-side, not a bad CSR.
            throw new AcmeProblemDocumentException(HttpStatus.INTERNAL_SERVER_ERROR, Problem.SERVER_INTERNAL);
        } catch (CertificateRequestException | IOException e) {
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

    private List<RequestAttribute> getClientOperationAttributes(boolean isRevoke, AcmeAccount acmeAccount,
            boolean isRaProfileBased) {
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
            return AttributeDefinitionUtils
                    .getClientAttributes(AttributeDefinitionUtils.deserialize(attributes, DataAttributeV2.class));
        } else {
            if (isRevoke) {
                return attributeEngine
                        .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                                .builder(com.otilm.api.model.core.auth.Resource.ACME_PROFILE,
                                        acmeAccount.getAcmeProfile().getUuid())
                                .connector(acmeAccount
                                        .getAcmeProfile()
                                        .getRaProfile()
                                        .getAuthorityInstanceReference()
                                        .getConnectorUuid())
                                .operation(AttributeOperation.CERTIFICATE_REVOKE)
                                .build());
            } else {
                return attributeEngine
                        .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                                .builder(com.otilm.api.model.core.auth.Resource.ACME_PROFILE,
                                        acmeAccount.getAcmeProfile().getUuid())
                                .connector(acmeAccount
                                        .getAcmeProfile()
                                        .getRaProfile()
                                        .getAuthorityInstanceReference()
                                        .getConnectorUuid())
                                .operation(AttributeOperation.CERTIFICATE_ISSUE)
                                .build());
            }
        }

    }

    /**
     * Submits the certificate request of a claimed order and returns the order as it stands afterwards. A failed
     * submission rolls back on the request's EntityManager, which clears it, so the order is re-read rather than
     * reused.
     */
    private AcmeOrder createCert(AcmeOrder order, ClientCertificateIssueRequestDto certificateIssueRequestDto) {
        Certificate certificate;
        try {
            // keep state as PROCESSING since issuing is async process
            if (logger.isDebugEnabled()) {
                logger
                        .debug("Requesting Certificate for the Order: {} and issue request: {}", order,
                                certificateIssueRequestDto);
            }
            ClientCertificateDataResponseDto certificateOutput = clientOperationService
                    .issueCertificate(SecuredParentUUID
                            .fromUUID(order.getAcmeAccount().getRaProfile().getAuthorityInstanceReferenceUuid()),
                            order.getAcmeAccount().getRaProfile().getSecuredUuid(), certificateIssueRequestDto,
                            CertificateProtocolInfo
                                    .Acme(order.getAcmeAccount().getAcmeProfileUuid(), order.getAcmeAccountUuid()));
            certificate = certificateService.getCertificateEntity(SecuredUUID.fromString(certificateOutput.getUuid()));
        } catch (Exception e) {
            logger.error("Issue Certificate failed. Exception: {}", e.getMessage());
            return acmeChallengeWriter.failFinalizeSubmission(order.getUuid());
        }
        return acmeChallengeWriter
                .recordFinalizeSubmission(order.getUuid(), AcmeRandomGeneratorAndValidator.generateRandomId(),
                        certificate);
    }

    protected ByteArrayResource getCertificateResource(String certificateId)
            throws NotFoundException, CertificateException {
        AcmeOrder order = acmeOrderRepository
                .findByCertificateId(certificateId)
                .orElseThrow(() -> new NotFoundException(Order.class, certificateId));
        LoggingHelper
                .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.ACME_ORDER, true, order.getUuid().toString(),
                        order.getOrderId());

        CertificateChainResponseDto certificateChainResponse = certificateService
                .getCertificateChain(SecuredUUID.fromUUID(order.getCertificateReferenceUuid()), true);
        if (!certificateChainResponse.getCertificates().isEmpty()) {
            LoggingHelper
                    .putLogResourceInfo(com.otilm.api.model.core.auth.Resource.CERTIFICATE, false,
                            certificateChainResponse.getCertificates().getFirst().getUuid(),
                            certificateChainResponse.getCertificates().getFirst().getSubjectDn());
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

    private void checkAccountConfiguration(AcmeAccount account, String profileName, boolean isRaProfileBased)
            throws AcmeProblemDocumentException {
        AcmeRaProfiles acmeRaProfiles = getProfiles(profileName, isRaProfileBased);

        if (!account.getAcmeProfileUuid().equals(acmeRaProfiles.acmeProfile.getUuid())
                || !account.getRaProfileUuid().equals(acmeRaProfiles.raProfile.getUuid())) {
            throw new AcmeProblemDocumentException(HttpStatus.UNAUTHORIZED, Problem.UNAUTHORIZED,
                    "Account does not belong to this profile");
        }
    }

    private AcmeRaProfiles getProfiles(String profileName, boolean isRaProfileBased)
            throws AcmeProblemDocumentException {
        AcmeProfile acmeProfile;
        RaProfile raProfileToUse;

        if (isRaProfileBased) {
            try {
                raProfileToUse = getRaProfileEntity(profileName);
            } catch (NotFoundException e) {
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                        "RA Profile is not found");
            }
            acmeProfile = raProfileToUse.getAcmeProfile();
        } else {
            try {
                acmeProfile = getAcmeProfileEntityByName(profileName);
            } catch (NotFoundException e) {
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                        "ACME Profile is not found");
            }
            raProfileToUse = acmeProfile.getRaProfile();
        }

        return new AcmeRaProfiles(acmeProfile, raProfileToUse);
    }

    private record AcmeRaProfiles(AcmeProfile acmeProfile, RaProfile raProfile) {
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // Validation of ACME requests
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    private void validateRequest(AcmeJwsRequest acmeJwsRequest, String acmeProfileName, URI requestUri,
            boolean isRaProfileBased) throws AcmeProblemDocumentException {
        validateRequestNoNonce(acmeJwsRequest, acmeProfileName, requestUri, isRaProfileBased);

        // Validate JWS Header for Nonce if it has the correct value
        validateNonce(acmeJwsRequest.getJwsHeader().getCustomParam("nonce"));
    }

    private void validateRequestNoNonce(AcmeJwsRequest acmeJwsRequest, String acmeProfileName, URI requestUri,
            boolean isRaProfileBased) throws AcmeProblemDocumentException {
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

        AcmeNonce acmeNonce = acmeNonceRepository
                .findByNonce(nonce.toString())
                .orElseThrow(() -> new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_NONCE));
        if (acmeNonce.getExpires().after(AcmeCommonHelper.addSeconds(new Date(), AcmeConstants.NONCE_VALIDITY))) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.BAD_NONCE);
        }
    }

    private void validateSignature(AcmeJwsRequest acmeJwsRequest) throws AcmeProblemDocumentException {
        if (acmeJwsRequest.isJwkPresent()) {
            if (!acmeJwsRequest.checkSignature(acmeJwsRequest.getPublicKey())) {
                throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.UNAUTHORIZED);
            }
        } else {
            String kid = acmeJwsRequest.getKid();
            AcmeAccount account = acmeAccountRepository
                    .findByAccountId(kid.substring(kid.lastIndexOf('/') + 1))
                    .orElseThrow(() -> new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST,
                            Problem.ACCOUNT_DOES_NOT_EXIST));
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
        RaProfile raProfile = raProfileRepository
                .findByName(raProfileName)
                .orElseThrow(() -> new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
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
        if (Boolean.TRUE.equals(acmeProfile.isDisableNewOrders())) {
            ProblemDocument problemDocument = new ProblemDocument(Problem.USER_ACTION_REQUIRED);
            problemDocument.setInstance(acmeProfile.getTermsOfServiceUrl());
            problemDocument.setDetail("Terms of service have changed");
            Map<String, String> additionalHeaders = new HashMap<>();
            additionalHeaders
                    .put("Link", "<" + acmeProfile.getTermsOfServiceChangeUrl() + ">;rel=\"terms-of-service\"");
            throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, problemDocument, additionalHeaders);
        }
    }

    private AcmeOrder validateOrder(String orderId) throws AcmeProblemDocumentException {
        AcmeOrder order = acmeOrderRepository
                .findByOrderId(orderId)
                .orElseThrow(() -> new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.SERVER_INTERNAL,
                        "Requested order is not found"));

        // An order that has requested or received a certificate takes its status from the certificate, decided
        // under the order lock, before a status left open behind it could be settled as a failure.
        order = acmeChallengeWriter.reconcileCertificateStatus(order.getUuid());
        settleStaleStatuses(order);

        if (order.getExpires() != null && order.getExpires().before(new Date())) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "Expiry of the order is reached");
        }

        return order;
    }

    /**
     * The account that signed the request must be the one the object belongs to. A request about an existing object has
     * to name its account with {@code kid} (RFC 8555 section 6.2); a key supplied inline proves only possession of that
     * key, not an account.
     */
    private void requireOwnership(AcmeJwsRequest jwsRequest, AcmeAccount owner) throws AcmeProblemDocumentException {
        if (jwsRequest.isJwkPresent()) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "The request must be signed with the account key and name the account");
        }
        String kid = jwsRequest.getKid();
        String requestAccountId = kid.substring(kid.lastIndexOf('/') + 1);
        if (!owner.getAccountId().equals(requestAccountId)) {
            throw new AcmeProblemDocumentException(HttpStatus.FORBIDDEN, Problem.UNAUTHORIZED,
                    "The requested object belongs to a different account");
        }
    }

    private AcmeAuthorization loadAuthorization(String authorizationId) throws AcmeProblemDocumentException {
        return acmeAuthorizationRepository
                .findByAuthorizationId(authorizationId)
                .orElseThrow(() -> new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.SERVER_INTERNAL,
                        "Requested authorization is not found"));
    }

    private void rejectExpiredAuthorization(AcmeAuthorization authorization) throws AcmeProblemDocumentException {
        rejectExpiredAuthorization(authorization, "Expiry of the authorization is reached");
    }

    private void rejectExpiredAuthorization(AcmeAuthorization authorization, String detail)
            throws AcmeProblemDocumentException {
        if (authorization.getExpires() != null && authorization.getExpires().before(new Date())) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED, detail);
        }
    }

    private AcmeChallenge loadChallenge(String challengeId) throws AcmeProblemDocumentException {
        return acmeChallengeRepository
                .findWithContextByChallengeId(challengeId)
                .orElseThrow(() -> new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.SERVER_INTERNAL,
                        "Requested challenge is not found"));
    }

    /**
     * Finds the certificate by the fingerprint of the DER encoding that the client sent, without parsing it. A request
     * signed with the key of the certificate needs no account, and parsing builds the public key of the certificate,
     * which costs seconds for a large key.
     */
    private Certificate loadCertificateToRevoke(byte[] certificateDer) throws AcmeProblemDocumentException {
        try {
            return certificateService.getCertificateEntityByFingerprint(CertificateUtil.getThumbprint(certificateDer));
        } catch (NotFoundException e) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    "Requested certificate is not found");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /**
     * The bytes of a member that RFC 8555 carries as base64url, such as the CSR to finalize an order with or the
     * certificate to revoke. A member that is missing, empty or not base64url is refused as malformed.
     */
    private static byte[] decodeBase64Url(String value, String member) throws AcmeProblemDocumentException {
        if (value == null || value.isEmpty()) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED, member + " is missing");
        }
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.MALFORMED,
                    member + " is not base64url-encoded");
        }
    }

    /**
     * Whether the request asks to deactivate the authorization (RFC 8555 section 7.5.2). A POST-as-GET request carries
     * an empty payload; any other payload is read strictly, before anything is settled for the authorization.
     */
    private static boolean isDeactivationRequest(AcmeJwsRequest jwsRequest) throws AcmeProblemDocumentException {
        if (jwsRequest.getJwsObject().getPayload().toString().isEmpty()) {
            return false;
        }
        AuthorizationUpdate update = AcmeJsonProcessor
                .getPayloadAsRequestObject(jwsRequest.getJwsObject(), AuthorizationUpdate.class);
        return "deactivated".equals(update.status());
    }

    /**
     * The public key of the old key of a key change, converted by its own type. A key that is not a JWK of a public key
     * is refused as a malformed payload, including one for which nimbus throws an unchecked exception, such as a
     * NullPointerException for an RSA key whose other primes lack their members.
     */
    private static PublicKey parseOldKey(Map<String, Object> oldKey) throws AcmeProblemDocumentException {
        try {
            if (JWK.parse(oldKey) instanceof AsymmetricJWK asymmetricJwk) {
                return asymmetricJwk.toPublicKey();
            }
        } catch (ParseException | JOSEException | RuntimeException e) {
            logger.error("Error while parsing JWS: {}", e.getMessage());
        }
        throw AcmeJsonProcessor.malformedPayload();
    }

    /** The payload of the inner JWS of a key change (RFC 8555 section 7.3.5). */
    private record KeyChange(String account, Map<String, Object> oldKey) {
    }

    /** The payload of a request to update an authorization (RFC 8555 section 7.5.2). */
    private record AuthorizationUpdate(String status) {
    }

    private void validateAccount(String accountId) throws AcmeProblemDocumentException {
        AcmeAccount acmeAccount = acmeAccountRepository
                .findByAccountId(accountId)
                .orElseThrow(
                        () -> new AcmeProblemDocumentException(HttpStatus.BAD_REQUEST, Problem.ACCOUNT_DOES_NOT_EXIST));
        validateAccount(acmeAccount);
    }

}
