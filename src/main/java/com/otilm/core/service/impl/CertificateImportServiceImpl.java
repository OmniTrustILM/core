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
import com.otilm.api.model.client.cryptography.key.KeyImportRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
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
import com.otilm.core.dao.entity.CertificateImportEntryState;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.exception.ImportIdReusedException;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.certificate.CertificateImportRecord;
import com.otilm.core.model.certificate.ImportedObjects;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.ExternalAuthorizationProgrammatic;
import com.otilm.core.service.CertificateImportExternalService;
import com.otilm.core.service.CertificateUploadService;
import com.otilm.core.service.CryptographicKeyImportExternalService;
import com.otilm.core.service.handler.KeyImportGates;
import com.otilm.core.service.writer.CertificateImportWriter;
import com.otilm.core.util.AuthHelper;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
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
 * Imports the entries a caller names from an uploaded file, each on its own, and records each under its requester and
 * import identifier, so that a replay is answered from the record and a reuse for anything else is refused.
 *
 * <p>
 * Whatever refuses a request is checked before anything is imported: the file, the selection, the reuse of an import
 * identifier and the permissions the entries that run need. A key goes to the key import as a file of its own, opened
 * with the file's passphrase; only once it is imported are the certificates of its chain registered, so that its leaf
 * links to it.
 * </p>
 */
@Service
@Transactional(propagation = Propagation.NOT_SUPPORTED)
public class CertificateImportServiceImpl implements CertificateImportExternalService {

    private static final String NOT_HELD = "The file holds no entry %s.";
    private static final String NO_SUCH_ENTRY = "The file holds no such entry.";
    private static final String SIGNING_REQUEST = "Entry %s is a certificate request, which cannot be imported.";
    private static final String NEEDS_DESTINATION = "Entry %s carries key material and needs a keyDestination.";
    private static final String TAKES_NO_DESTINATION = "Entry %s carries no key material, so it takes no keyDestination.";
    private static final String NEEDS_NAME = "Entry %s needs a keyName: it has no alias or certificate common name to take one from.";
    private static final String NOT_A_UUID = "tokenProfileUuid must be a UUID";
    private static final String REUSED = "The importId of entry %s was already used to import something else.";
    private static final String NOT_REGISTERED = "A certificate of the entry was not uploaded. See Certificate Uploaded Event History for more details.";
    private static final String NOT_IMPORTED = "The entry could not be imported. Retry it, or see the Core log for why.";

    /** What an entry reference looks like; anything else a caller names an entry by is not repeated. */
    private static final Pattern REFERENCE = Pattern.compile("[0-9a-f]{64}");

    private static final Logger logger = LoggerFactory.getLogger(CertificateImportServiceImpl.class);

    private final AuthorizationEnforcer authorizationEnforcer;
    private final KeyImportGates keyImportGates;
    private final ContainerReader containerReader;
    private final CertificateImportWriter certificateImportWriter;
    private final CryptographicKeyImportExternalService cryptographicKeyImportService;
    private final CertificateUploadService certificateUploadService;
    private final CertificateRepository certificateRepository;
    private final AttributeEngine attributeEngine;

    private AuditOperationDataOverride auditOperationDataOverride;

    public CertificateImportServiceImpl(AuthorizationEnforcer authorizationEnforcer, KeyImportGates keyImportGates,
            ContainerReader containerReader, CertificateImportWriter certificateImportWriter,
            CryptographicKeyImportExternalService cryptographicKeyImportService,
            CertificateUploadService certificateUploadService, CertificateRepository certificateRepository,
            AttributeEngine attributeEngine) {
        this.authorizationEnforcer = authorizationEnforcer;
        this.keyImportGates = keyImportGates;
        this.containerReader = containerReader;
        this.certificateImportWriter = certificateImportWriter;
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
                UUID requester = UUID.fromString(AuthHelper.getUserIdentification().getUuid());
                List<Selection> selections = recorded(requester, selections(container, request));
                List<Selection> running = selections.stream().filter(Selection::runs).toList();
                if (running.stream().anyMatch(Selection::registersCertificates)) {
                    authorizationEnforcer.enforce(Resource.CERTIFICATE, ResourceAction.CREATE);
                }
                Context context = new Context(requester, request.getPassphrase(), request.getCustomAttributes(),
                        requireProfiles(running));
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
        List<Selection> selections = new ArrayList<>();
        for (CertificateImportEntryDto requested : request.getEntries()) {
            selections.add(selection(container, requested, request.getCustomAttributes()));
        }
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
    private static Selection selection(Container container, CertificateImportEntryDto requested,
            List<RequestAttribute> certificateCustomAttributes) {
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
            return new Selection(requested, entry, CertificateImportDigest.of(requested, certificateCustomAttributes),
                    null, null, null);
        }
        if (destination == null) {
            throw refusal(NEEDS_DESTINATION, reference);
        }
        String keyName = keyNameOf(key, destination).orElseThrow(() -> refusal(NEEDS_NAME, reference));
        UUID profileUuid = profileUuidOf(destination);
        return new Selection(requested, key, CertificateImportDigest.of(requested, certificateCustomAttributes),
                profileUuid, keyName, null);
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

    /**
     * Each selection with the record of its importId, when there is one; a record with another digest refuses the
     * request.
     */
    private List<Selection> recorded(UUID requester, List<Selection> selections) {
        List<Selection> recorded = new ArrayList<>();
        for (Selection selection : selections) {
            Optional<CertificateImportRecord> found = certificateImportWriter.find(requester, selection.importId());
            if (found.isPresent() && !found.get().digest().equals(selection.digest())) {
                throw reused(selection);
            }
            recorded.add(found.map(selection::recordedAs).orElse(selection));
        }
        return recorded;
    }

    /** The destination profiles of the entries that run, each found and open to the caller for a key import. */
    private Map<UUID, TokenProfileFullModel> requireProfiles(List<Selection> running) throws NotFoundException {
        Map<UUID, TokenProfileFullModel> profiles = new HashMap<>();
        for (Selection selection : running) {
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
        List<CertificateImportResultDto> results = new ArrayList<>();
        for (Selection selection : selections) {
            results.add(selection.runs() ? imported(context, selection) : answered(selection, selection.recorded()));
        }
        nameInAuditRecord(new ImportedObjects(distinct(results, CertificateImportResultDto::getCertificateUuid),
                distinct(results, CertificateImportResultDto::getKeyUuid)));
        CertificateImportResponseDto response = new CertificateImportResponseDto();
        response.setResults(results);
        return response;
    }

    /**
     * Names in the audit record the certificates and keys the results name, as the operation's data, and the
     * certificate as the resource object when they name exactly one. Each key import named its key as the resource
     * object, which this replaces.
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

    /**
     * The entry imported on its own: its record is opened, or reused while open, as it starts and completed with what
     * the entry produced. A failure is the entry's result and leaves the record open, so a replay retries the entry; a
     * key imported before the failure is named in the result.
     */
    private CertificateImportResultDto imported(Context context, Selection selection) {
        UUID keyUuid = null;
        try {
            CertificateImportRecord recorded = selection.recorded() != null
                    ? selection.recorded()
                    : opened(context.requester(), selection);
            if (recorded.state() == CertificateImportEntryState.COMPLETED) {
                return answered(selection, recorded);
            }
            if (selection.entry() instanceof KeyEntry key) {
                keyUuid = importedKey(context, selection, key);
            }
            UUID certificateUuid = registeredCertificate(context, selection);
            certificateImportWriter.complete(recorded.uuid(), certificateUuid, keyUuid);
            return succeeded(selection, certificateUuid, keyUuid);
        } catch (ConnectorException | NotFoundException | AttributeException | CertificateException | IOException
                | RuntimeException failure) {
            if (failure instanceof AccessDeniedException denied) {
                throw denied;
            }
            return failed(selection, keyUuid, messageOf(selection, failure));
        }
    }

    /**
     * The entry's new record, or the record a concurrent request opened for the same entry since it was looked up. A
     * concurrent request that recorded the importId for something else refuses the entry.
     */
    private CertificateImportRecord opened(UUID requester, Selection selection) {
        try {
            return certificateImportWriter.open(requester, selection.importId(), selection.digest());
        } catch (AlreadyExistException recordedMeanwhile) {
            throw reused(selection);
        }
    }

    /**
     * The certificate the entry registers once its key, if any, is imported: a key's leaf, registered with its chain,
     * or the entry's certificate; {@code null} for a key without a leaf.
     */
    private UUID registeredCertificate(Context context, Selection selection) throws CertificateException, IOException {
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
    private UUID importedKey(Context context, Selection selection, KeyEntry key)
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
            KeyDetailDto imported = cryptographicKeyImportService
                    .importKey(profile.tokenInstance().uuid(), profile.uuid(), type, request);
            return UUID.fromString(imported.getUuid());
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
    private UUID registeredChain(KeyEntry key, List<RequestAttribute> customAttributes)
            throws CertificateException, IOException {
        for (X509CertificateHolder issuer : key.issuers().reversed()) {
            registered(issuer, customAttributes);
        }
        return registered(key.leaf(), customAttributes);
    }

    /**
     * The UUID of the certificate in the inventory, registered through the synchronous upload unless it is there
     * already; one already there keeps its custom attributes.
     */
    private UUID registered(X509CertificateHolder certificate, List<RequestAttribute> customAttributes)
            throws CertificateException, IOException {
        byte[] der = certificate.getEncoded();
        String fingerprint = EntryReference.of(der);
        Optional<UUID> registered = inventoried(fingerprint);
        if (registered.isPresent()) {
            return registered.get();
        }
        try {
            certificateUploadService.upload(Base64.getEncoder().encodeToString(der), customAttributes, true);
        } catch (AlreadyExistException registeredMeanwhile) {
            // Another request registered the certificate since it was looked up, which is all this one was to do.
        }
        return inventoried(fingerprint).orElseThrow(() -> new CertificateException(NOT_REGISTERED));
    }

    private Optional<UUID> inventoried(String fingerprint) {
        return certificateRepository.findByFingerprint(fingerprint).map(Certificate::getUuid);
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

    private static CertificateImportResultDto answered(Selection selection, CertificateImportRecord recorded) {
        return succeeded(selection, recorded.certificateUuid(), recorded.keyUuid());
    }

    private static CertificateImportResultDto succeeded(Selection selection, UUID certificateUuid, UUID keyUuid) {
        CertificateImportResultDto result = resultOf(selection);
        result.setImported(true);
        result.setCertificateUuid(Objects.toString(certificateUuid, null));
        result.setKeyUuid(Objects.toString(keyUuid, null));
        return result;
    }

    private static CertificateImportResultDto failed(Selection selection, UUID keyUuid, String message) {
        CertificateImportResultDto result = resultOf(selection);
        result.setKeyUuid(Objects.toString(keyUuid, null));
        result.setMessage(message);
        return result;
    }

    private static CertificateImportResultDto resultOf(Selection selection) {
        CertificateImportResultDto result = new CertificateImportResultDto();
        result.setEntryReference(selection.entry().reference());
        result.setKind(selection.entry().kind());
        return result;
    }

    private static ImportIdReusedException reused(Selection selection) {
        return new ImportIdReusedException(REUSED.formatted(selection.entry().reference()));
    }

    private static ValidationException refusal(String message, String name) {
        return new ValidationException(ValidationError.create(message.formatted(name)));
    }

    /**
     * An entry the request names.
     *
     * @param requested the entry as the request names it
     * @param entry what the file holds for it
     * @param digest what the entry asks for, as its record keeps it
     * @param profileUuid the UUID of the token profile its key goes to, or {@code null} for a certificate
     * @param keyName the name its key is imported under, or {@code null} for a certificate
     * @param recorded the record of its importId, or {@code null} when it has none yet
     */
    private record Selection(CertificateImportEntryDto requested, ContainerEntry entry, String digest, UUID profileUuid,
            String keyName, CertificateImportRecord recorded) {

        String importId() {
            return requested.getImportId();
        }

        Selection recordedAs(CertificateImportRecord found) {
            return new Selection(requested, entry, digest, profileUuid, keyName, found);
        }

        /** Whether the entry is to run, which it does until its record is completed. */
        boolean runs() {
            return recorded == null || recorded.state() != CertificateImportEntryState.COMPLETED;
        }

        /** Whether running the entry registers a certificate: a certificate, or a key with its leaf. */
        boolean registersCertificates() {
            return entry instanceof CertificateEntry || (entry instanceof KeyEntry key && key.leaf() != null);
        }
    }

    /**
     * What the entries that run share.
     *
     * @param requester the UUID of the user the entries are recorded under
     * @param passphrase the passphrase that opens the file, or {@code null}
     * @param certificateCustomAttributes the custom attributes of the certificates registered, or {@code null}
     * @param profiles the destination profiles of the entries, by UUID
     */
    private record Context(UUID requester, Passphrase passphrase, List<RequestAttribute> certificateCustomAttributes,
            Map<UUID, TokenProfileFullModel> profiles) {
    }
}
