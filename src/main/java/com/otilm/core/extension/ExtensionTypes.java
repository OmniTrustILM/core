package com.otilm.core.extension;

import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Finds the ASN.1 type governing an extension's value: the module an operator registered for the OID, or the one Core
 * ships for a standard extension.
 *
 * <p>
 * An OID with no module is not an error. Its value is DER the requester supplies as bytes, the way to carry an
 * extension nobody has described.
 */
public final class ExtensionTypes {

    private static final Map<String, Optional<String>> SHIPPED = new ConcurrentHashMap<>();
    private static final int MAX_PARSED = 256;
    /** Least recently used out first; an OID deleted or stripped of its module is dropped on the next resolve too. */
    private static final Map<String, Parsed> PARSED = Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Parsed> eldest) {
            return size() > MAX_PARSED;
        }
    });

    /** A parsed module with the text it came from, so an edit to the OID replaces it rather than sitting beside it. */
    private record Parsed(String module, ExtensionType type) {
    }

    private ExtensionTypes() {
    }

    /** The type governing {@code oid}'s value, or empty when neither the registry nor Core describes it. */
    public static Optional<ExtensionType> resolve(String oid) {
        Optional<String> module = module(oid);
        if (module.isEmpty()) {
            PARSED.remove(oid);
        }
        return module.map(text -> parse(oid, text));
    }

    /**
     * The module text for {@code oid}, which the OID API shows so an operator can read what their values must satisfy.
     *
     * <p>
     * A custom entry is the effective one while it exists, the same way its criticality and encoding are. An entry
     * declaring no module therefore means the extension is undescribed, not that a Core-shipped module applies - which
     * would otherwise start constraining a legacy row whose OID has since become a system OID.
     */
    public static Optional<String> module(String oid) {
        Map<String, OidRecord> registry = OidHandler.getOidCache(OidCategory.CERTIFICATE_EXTENSION);
        OidRecord entry = registry == null ? null : registry.get(oid);
        if (entry != null && entry.valueSchema() != null) {
            return Optional.of(entry.valueSchema());
        }
        if (entry != null && !entry.system()) {
            return Optional.empty();
        }
        return shippedModule(oid);
    }

    /** The module Core ships for a standard extension, or empty when it ships none. */
    public static Optional<String> shippedModule(String oid) {
        // A classpath resource cannot change while the process runs, so the miss is worth caching too.
        return SHIPPED.computeIfAbsent(oid, ExtensionTypes::readShippedModule);
    }

    private static Optional<String> readShippedModule(String oid) {
        try (InputStream resource = ExtensionTypes.class
                .getClassLoader()
                .getResourceAsStream("extension-modules/" + oid + ".asn1")) {
            if (resource == null) {
                return Optional.empty();
            }
            return Optional.of(new String(resource.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException("Core-shipped ASN.1 module for " + oid + " is unreadable", e);
        }
    }

    /**
     * Parses a module, keeping one result per OID, replacing it when the OID's text changes, and letting the least
     * recently used go once the registry outgrows the bound. Registration rejects a module this cannot read, so
     * reaching here with one means a row written straight into the database - and then the failure belongs to whoever
     * asks for it rather than to every later request.
     */
    private static ExtensionType parse(String oid, String module) {
        Parsed cached = PARSED.get(oid);
        if (cached == null || !cached.module().equals(module)) {
            cached = new Parsed(module, Asn1ModuleReader.read(module));
            PARSED.put(oid, cached);
        }
        return cached.type();
    }
}
