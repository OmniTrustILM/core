package com.otilm.core.service.impl;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.PlatformException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.certificate.CertificateEntryKeyDestinationDto;
import com.otilm.api.model.client.certificate.CertificateImportEntryDto;
import com.otilm.api.model.client.certificate.CertificateImportRequestDto;
import com.otilm.api.model.client.certificate.CertificateImportResponseDto;
import com.otilm.api.model.client.certificate.CertificateImportResultDto;
import com.otilm.api.model.client.certificate.ImportOutcome;
import com.otilm.api.model.client.cryptography.key.KeyImportRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.api.model.core.secret.UploadedFile;
import com.otilm.core.aop.AuditOperationDataOverride;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.container.CertificateEntry;
import com.otilm.core.container.Container;
import com.otilm.core.container.ContainerEntry;
import com.otilm.core.container.ContainerReader;
import com.otilm.core.container.EntryReference;
import com.otilm.core.container.KeyEntry;
import com.otilm.core.container.SigningRequestEntry;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.certificate.ImportedObjects;
import com.otilm.core.model.crypto.ImportedKey;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorizationProgrammatic;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateImportExternalService;
import com.otilm.core.service.CertificateUploadService;
import com.otilm.core.service.CryptographicKeyImportExternalService;
import com.otilm.core.service.handler.KeyImportGates;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * Imports the entries a caller names from an uploaded file, each on its own and each worked out again whenever it is
 * named: a certificate already in the inventory is found by its fingerprint, and the key import answers a repeat with
 * the key it imported, so a resent request imports nothing twice.
 *
 * <p>
 * Whatever refuses a request is checked before anything is imported: the file, the selection and the permissions the
 * entries need. A key goes to the key import as a file of its own, opened with the file's passphrase; only once it is
 * imported are the certificates of its chain registered, so that its leaf links to it.
 * </p>
 *
 * <p>
 * Each result says what became of the entry's certificate, a key's leaf for a key: created by this call, or found in
 * the inventory and left as it is. Either way it is named by its UUID only to a caller who may see it in detail: the
 * upload gives a certificate no owner, so a caller without that permission could not open even one it created.
 * </p>
 *
 * <p>
 * It says what became of the entry's key too: created by this call, taken into the public-key-only record that holds
 * its public key, or found in the inventory and left as it is. A key found there is named by its UUID only to a caller
 * who may see it in detail; the caller owns a key it created, and was allowed to update a record it took the key into.
 * </p>
 */
@Service
@Transactional(propagation = Propagation.NOT_SUPPORTED, rollbackFor = Exception.class)
public class CertificateImportServiceImpl implements CertificateImportExternalService {

    private static final String NOT_HELD = "The file holds no entry %s.";
    private static final String NO_SUCH_ENTRY = "The file holds no such entry.";
    private static final String SIGNING_REQUEST = "Entry %s is a certificate request, which cannot be imported.";
    private static final String NEEDS_DESTINATION = "Entry %s carries key material and needs a keyDestination.";
    private static final String TAKES_NO_DESTINATION = "Entry %s carries no key material, so it takes no keyDestination.";
    private static final String NEEDS_NAME = "Entry %s needs a keyName: it has no alias or certificate common name to take one from.";
    private static final String NOT_A_UUID = "tokenProfileUuid must be a UUID";
    private static final String NOT_REGISTERED = "A certificate of the entry was not uploaded. See Certificate Uploaded Event History for more details.";
    private static final String NOT_IMPORTED = "The entry could not be imported. Retry it, or see the Core log for why.";

    /** What an entry reference looks like; anything else a caller names an entry by is not repeated. */
    private static final Pattern REFERENCE = Pattern.compile("[0-9a-f]{64}");

    private static final Logger logger = LoggerFactory.getLogger(CertificateImportServiceImpl.class);

    private final AuthorizationEnforcer authorizationEnforcer;
    private final KeyImportGates keyImportGates;
    private final ContainerReader containerReader;
    private final CryptographicKeyImportExternalService cryptographicKeyImportService;
    private final CertificateUploadService certificateUploadService;
    private final CertificateRepository certificateRepository;
    private final AttributeEngine attributeEngine;

    private AuditOperationDataOverride auditOperationDataOverride;

    public CertificateImportServiceImpl(AuthorizationEnforcer authorizationEnforcer, KeyImportGates keyImportGates,
            ContainerReader containerReader, CryptographicKeyImportExternalService cryptographicKeyImportService,
            CertificateUploadService certificateUploadService, CertificateRepository certificateRepository,
            AttributeEngine attributeEngine) {
        this.authorizationEnforcer = authorizationEnforcer;
        this.keyImportGates = keyImportGates;
        this.containerReader = containerReader;
        this.cryptographicKeyImportService = cryptographicKeyImportService;
        this.certificateUploadService = certificateUploadService;
        this.certificateRepository = certificateRepository;
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setAuditOperationDataOverride(AuditOperationDataOverride auditOperationDataOverride) {
        this.auditOperationDataOverride = auditOperationDataOverride;
    }

    /**
     * Checks before the file is read that the caller may import certificates or keys; what else the caller must be
     * permitted depends on what the named entries turn out to be. The copy of the file read and the keys the file's
     * entries keep are overwritten whatever the outcome.
     */
    @Override
    @ExternalAuthorizationProgrammatic(resource = Resource.CERTIFICATE, action = ResourceAction.CREATE)
    public CertificateImportResponseDto importCertificates(CertificateImportRequestDto request)
            throws NotFoundException {
        try {
            authorizationEnforcer.enforce(Resource.CERTIFICATE, ResourceAction.CREATE);
        } catch (AccessDeniedException e) {
            authorizationEnforcer.enforce(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.IMPORT_KEY);
        }
        byte[] file = request.getFile().content();
        try {
            Container container = containerReader.read(file, request.getPassphrase());
            try {
                List<Selection> selections = selections(container, request);
                if (selections.stream().anyMatch(Selection::registersCertificates)) {
                    authorizationEnforcer.enforce(Resource.CERTIFICATE, ResourceAction.CREATE);
                }
                Context context = new Context(request.getPassphrase(), request.getCustomAttributes(),
                        requireProfiles(selections));
                return responseOf(context, selections);
            } finally {
                container.clear();
            }
        } finally {
            Arrays.fill(file, (byte) 0);
        }
    }

    /**
     * The entries the request names, each checked against what the file holds for it, and their certificates' custom
     * attributes.
     */
    private List<Selection> selections(Container container, CertificateImportRequestDto request) {
        List<Selection> selections = request
                .getEntries()
                .stream()
                .map(requested -> selection(container, requested))
                .toList();
        List<RequestAttribute> customAttributes = request.getCustomAttributes();
        if (customAttributes != null && !customAttributes.isEmpty()) {
            attributeEngine.validateCustomAttributesContent(Resource.CERTIFICATE, customAttributes);
        }
        return selections;
    }

    /**
     * The entry the file holds for the reference, with a key destination exactly when the entry carries a key. Every
     * refusal but the first names an entry the file holds, whose reference is the file's own.
     */
    private static Selection selection(Container container, CertificateImportEntryDto requested) {
        String reference = requested.getEntryReference();
        ContainerEntry entry = container.entry(reference).orElseThrow(() -> notHeld(reference));
        CertificateEntryKeyDestinationDto destination = requested.getKeyDestination();
        if (entry instanceof SigningRequestEntry) {
            throw refusal(SIGNING_REQUEST, reference);
        }
        if (!(entry instanceof KeyEntry key)) {
            if (destination != null) {
                throw refusal(TAKES_NO_DESTINATION, reference);
            }
            return new Selection(requested, entry, null, null);
        }
        if (destination == null) {
            throw refusal(NEEDS_DESTINATION, reference);
        }
        String keyName = keyNameOf(key, destination).orElseThrow(() -> refusal(NEEDS_NAME, reference));
        return new Selection(requested, key, profileUuidOf(destination), keyName);
    }

    /** The refusal of a reference the file holds no entry for, which repeats it only when it is a reference. */
    private static ValidationException notHeld(String reference) {
        return REFERENCE.matcher(reference).matches()
                ? refusal(NOT_HELD, reference)
                : new ValidationException(ValidationError.create(NO_SUCH_ENTRY));
    }

    /** The key's name: the one the destination gives, otherwise the key's alias, otherwise its leaf's common name. */
    private static Optional<String> keyNameOf(KeyEntry key, CertificateEntryKeyDestinationDto destination) {
        return Stream
                .of(destination.getKeyName(), key.alias(), commonNameOf(key.leaf()))
                .filter(StringUtils::isNotBlank)
                .findFirst();
    }

    /** The last common name of the certificate's subject, as the inventory takes it, or {@code null}. */
    private static String commonNameOf(X509CertificateHolder certificate) {
        if (certificate == null) {
            return null;
        }
        return Arrays
                .stream(certificate.getSubject().getRDNs(BCStyle.CN))
                .flatMap(name -> Arrays.stream(name.getTypesAndValues()))
                .filter(value -> BCStyle.CN.equals(value.getType()))
                .map(value -> value.getValue().toString())
                .reduce((first, last) -> last)
                .orElse(null);
    }

    private static UUID profileUuidOf(CertificateEntryKeyDestinationDto destination) {
        try {
            return UUID.fromString(destination.getTokenProfileUuid());
        } catch (IllegalArgumentException e) {
            throw new ValidationException(ValidationError.create(NOT_A_UUID));
        }
    }

    /** The destination profiles of the entries, each found and open to the caller for a key import. */
    private Map<UUID, TokenProfileFullModel> requireProfiles(List<Selection> selections) throws NotFoundException {
        Map<UUID, TokenProfileFullModel> profiles = new HashMap<>();
        for (Selection selection : selections) {
            UUID profileUuid = selection.profileUuid();
            if (profileUuid != null && !profiles.containsKey(profileUuid)) {
                profiles.put(profileUuid, keyImportGates.requireAccess(profileUuid));
                authorizationEnforcer.enforce(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.IMPORT_KEY);
            }
        }
        return profiles;
    }

    /** One result per selection, in request order, and what they produced named in the audit record. */
    private CertificateImportResponseDto responseOf(Context context, List<Selection> selections) {
        List<CertificateImportResultDto> results = selections
                .stream()
                .map(selection -> imported(context, selection))
                .toList();
        nameInAuditRecord(new ImportedObjects(distinct(results, CertificateImportResultDto::getCertificateUuid),
                distinct(results, CertificateImportResultDto::getKeyUuid)));
        CertificateImportResponseDto response = new CertificateImportResponseDto();
        response.setResults(results);
        return response;
    }

    /**
     * Names in the audit record the certificates and keys the results name, as the operation's data, and the
     * certificate as the resource object when they name exactly one, in place of any object named before.
     */
    private void nameInAuditRecord(ImportedObjects produced) {
        LoggingHelper.clearLogResourceObject();
        if (produced.certificateUuids().size() == 1) {
            LoggingHelper.putLogResourceInfo(Resource.CERTIFICATE, false, produced.certificateUuids().getFirst(), null);
        }
        // The override is request-scoped: outside an HTTP request there is none, and the audit reads none.
        if (RequestContextHolder.getRequestAttributes() != null) {
            auditOperationDataOverride.set(produced);
        }
    }

    private static List<String> distinct(List<CertificateImportResultDto> results,
            Function<CertificateImportResultDto, String> uuidOf) {
        return results.stream().map(uuidOf).filter(Objects::nonNull).distinct().toList();
    }

    /** The entry imported on its own. A failure is the entry's result, which names a key imported before it. */
    private CertificateImportResultDto imported(Context context, Selection selection) {
        ReportedKey key = null;
        try {
            if (selection.entry() instanceof KeyEntry keyEntry) {
                key = reported(importedKey(context, selection, keyEntry));
            }
            Registered certificate = registeredCertificate(context, selection);
            return succeeded(selection, certificate, key);
        } catch (ConnectorException | NotFoundException | AttributeException | CertificateException | IOException
                | RuntimeException failure) {
            if (failure instanceof AccessDeniedException denied) {
                throw denied;
            }
            return failed(selection, key, messageOf(selection, failure));
        }
    }

    /**
     * The certificate the entry registers once its key, if any, is imported: a key's leaf, registered with its chain,
     * or the entry's certificate; {@code null} for a key without a leaf.
     */
    private Registered registeredCertificate(Context context, Selection selection)
            throws CertificateException, IOException {
        if (selection.entry() instanceof KeyEntry key) {
            return key.leaf() == null ? null : registeredChain(key, context.certificateCustomAttributes());
        }
        CertificateEntry certificate = (CertificateEntry) selection.entry();
        return registered(certificate.certificate(), context.certificateCustomAttributes());
    }

    /**
     * The key imported as a file of its own, opened with the passphrase the reader opened it with. The copies of the
     * key and the passphrase handed to the key import are overwritten whatever the outcome. A key of an algorithm the
     * platform does not support is refused as the inspection reports it, before the key import, which cannot tell such
     * a key from one the passphrase does not open.
     */
    private Registered importedKey(Context context, Selection selection, KeyEntry key)
            throws ConnectorException, NotFoundException, AttributeException {
        if (!key.description().supported()) {
            throw new ValidationException(ValidationError.create(FileInspectionServiceImpl.UNSUPPORTED_ALGORITHM));
        }
        CertificateEntryKeyDestinationDto destination = selection.requested().getKeyDestination();
        TokenProfileFullModel profile = context.profiles().get(selection.profileUuid());
        KeyImportRequestDto request = new KeyImportRequestDto();
        request.setName(selection.keyName());
        request.setExportable(destination.getExportable());
        request.setImportAttributes(destination.getImportAttributes());
        request.setCustomAttributes(destination.getCustomAttributes());
        request.setFile(new UploadedFile(key.keyFile()));
        request.setInputPassphrase(copyOf(ContainerReader.opening(context.passphrase())));
        try {
            KeyRequestType type = key.secret() ? KeyRequestType.SECRET : KeyRequestType.KEY_PAIR;
            ImportedKey imported = cryptographicKeyImportService
                    .importKeyWithOutcome(profile.tokenInstance().uuid(), profile.uuid(), type, request);
            return new Registered(imported.key().uuid(), imported.outcome());
        } finally {
            request.getFile().clear();
            request.getInputPassphrase().clear();
        }
    }

    private static Passphrase copyOf(Passphrase passphrase) {
        char[] characters = passphrase.characters();
        try {
            return new Passphrase(characters);
        } finally {
            Arrays.fill(characters, '\0');
        }
    }

    /** The leaf, registered after its issuers from the farthest to the nearest, so each finds its issuer registered. */
    private Registered registeredChain(KeyEntry key, List<RequestAttribute> customAttributes)
            throws CertificateException, IOException {
        for (X509CertificateHolder issuer : key.issuers().reversed()) {
            registered(issuer, customAttributes);
        }
        return registered(key.leaf(), customAttributes);
    }

    /**
     * The certificate as the inventory holds it: one already there is left as it is, custom attributes and all, and any
     * other is registered through the synchronous upload. The upload checks that the certificate is not there before it
     * inserts it, so another request registering it at the same time makes the upload fail on the unique fingerprint;
     * the certificate is then the one that request registered. A failure with no such certificate stands, as do the
     * upload's refusal of the certificate and a denial of permission, which no other request explains.
     */
    private Registered registered(X509CertificateHolder certificate, List<RequestAttribute> customAttributes)
            throws CertificateException, IOException {
        byte[] der = certificate.getEncoded();
        String fingerprint = EntryReference.of(der);
        Optional<Registered> existing = inventoried(fingerprint, ImportOutcome.EXISTING);
        if (existing.isPresent()) {
            return existing.get();
        }
        try {
            certificateUploadService.upload(Base64.getEncoder().encodeToString(der), customAttributes, true);
        } catch (AlreadyExistException registeredMeanwhile) {
            // Another request registered the certificate since it was looked up.
            return inventoried(fingerprint, ImportOutcome.EXISTING)
                    .orElseThrow(() -> new CertificateException(NOT_REGISTERED));
        } catch (AccessDeniedException denied) {
            throw denied;
        } catch (RuntimeException failure) {
            return inventoried(fingerprint, ImportOutcome.EXISTING).orElseThrow(() -> failure);
        }
        return inventoried(fingerprint, ImportOutcome.CREATED)
                .orElseThrow(() -> new CertificateException(NOT_REGISTERED));
    }

    private Optional<Registered> inventoried(String fingerprint, ImportOutcome outcome) {
        return certificateRepository
                .findByFingerprint(fingerprint)
                .map(Certificate::getUuid)
                .map(uuid -> new Registered(uuid, outcome));
    }

    /**
     * The object's UUID when the caller may see the object in detail; {@code null} otherwise, and the result then names
     * the object by its outcome only.
     */
    private UUID shownUuidOf(Resource resource, UUID uuid) {
        try {
            authorizationEnforcer.enforce(resource, ResourceAction.DETAIL, SecuredUUID.fromUUID(uuid));
            return uuid;
        } catch (AccessDeniedException hidden) {
            return null;
        }
    }

    /**
     * The key as the result names it: by its UUID, unless the inventory held the key already and the caller may not see
     * it in detail.
     */
    private ReportedKey reported(Registered key) {
        UUID shownUuid = key.outcome() == ImportOutcome.EXISTING
                ? shownUuidOf(Resource.CRYPTOGRAPHIC_KEY, key.uuid())
                : key.uuid();
        return new ReportedKey(key.outcome(), shownUuid);
    }

    /**
     * Why the entry was not imported, in the platform's words: a refusal's messages joined, a certificate the upload
     * did not register named as such, and any other failure by its message only when the platform wrote it.
     */
    private static String messageOf(Selection selection, Exception failure) {
        if (failure instanceof ValidationException refusal) {
            return refusal
                    .getErrors()
                    .stream()
                    .map(ValidationError::getErrorDescription)
                    .collect(Collectors.joining(" "));
        }
        if (failure instanceof CertificateException) {
            return NOT_REGISTERED;
        }
        if (!(failure instanceof PlatformException)) {
            String reference = selection.entry().reference();
            logger.warn("Entry {} of a certificate import failed", reference, failure);
        }
        return PlatformException.safeMessage(failure, NOT_IMPORTED);
    }

    private CertificateImportResultDto succeeded(Selection selection, Registered certificate, ReportedKey key) {
        CertificateImportResultDto result = resultOf(selection, key);
        result.setImported(true);
        if (certificate != null) {
            result.setCertificateOutcome(certificate.outcome());
            result.setCertificateUuid(Objects.toString(shownUuidOf(Resource.CERTIFICATE, certificate.uuid()), null));
        }
        return result;
    }

    private static CertificateImportResultDto failed(Selection selection, ReportedKey key, String message) {
        CertificateImportResultDto result = resultOf(selection, key);
        result.setMessage(message);
        return result;
    }

    /** The entry's result, with what became of its key, when a key was imported. */
    private static CertificateImportResultDto resultOf(Selection selection, ReportedKey key) {
        CertificateImportResultDto result = new CertificateImportResultDto();
        result.setEntryReference(selection.entry().reference());
        result.setKind(selection.entry().kind());
        if (key != null) {
            result.setKeyOutcome(key.outcome());
            result.setKeyUuid(Objects.toString(key.shownUuid(), null));
        }
        return result;
    }

    private static ValidationException refusal(String message, String name) {
        return new ValidationException(ValidationError.create(message.formatted(name)));
    }

    /**
     * An entry the request names.
     *
     * @param requested the entry as the request names it
     * @param entry what the file holds for it
     * @param profileUuid the UUID of the token profile its key goes to, or {@code null} for a certificate
     * @param keyName the name its key is imported under, or {@code null} for a certificate
     */
    private record Selection(CertificateImportEntryDto requested, ContainerEntry entry, UUID profileUuid,
            String keyName) {

        /** Whether importing the entry registers a certificate: a certificate, or a key with its leaf. */
        boolean registersCertificates() {
            return entry instanceof CertificateEntry || (entry instanceof KeyEntry key && key.leaf() != null);
        }
    }

    /**
     * A certificate or key of an entry, as the inventory holds it.
     *
     * @param uuid its UUID
     * @param outcome {@link ImportOutcome#CREATED} when this call made it, {@link ImportOutcome#ADOPTED} for a key it
     * took into a public-key-only record, {@link ImportOutcome#EXISTING} when the inventory held it already
     */
    private record Registered(UUID uuid, ImportOutcome outcome) {
    }

    /**
     * An entry's key as the result names it.
     *
     * @param outcome what became of the key
     * @param shownUuid its UUID, or {@code null} when the caller may not see it in detail
     */
    private record ReportedKey(ImportOutcome outcome, UUID shownUuid) {
    }

    /**
     * What the entries share.
     *
     * @param passphrase the passphrase that opens the file, or {@code null}
     * @param certificateCustomAttributes the custom attributes of the certificates registered, or {@code null}
     * @param profiles the destination profiles of the entries, by UUID
     */
    private record Context(Passphrase passphrase, List<RequestAttribute> certificateCustomAttributes,
            Map<UUID, TokenProfileFullModel> profiles) {
    }
}
