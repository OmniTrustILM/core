package com.otilm.core.cbom.asset.identity;

import java.util.ArrayList;
import java.util.List;

/**
 * The normalized view of one cryptographic-asset component: the typed slots, and the provenance of how each was
 * decided.
 *
 * <p>
 * Mutable during derivation and read-only afterwards, because the steps depend on each other in order -- the family
 * decides whether a name may contribute a curve, the parameter set decides which digit runs the variant may keep, and
 * the mode decides which token the variant must not repeat.
 *
 * <p>
 * <b>Not everything here is keyed.</b> {@link #primitive()} is stored, indexed and filterable but never enters an
 * identity tuple: three producers describing one RSA-2048 emit {@code signature}, {@code pke} and {@code kem}, so it is
 * a producer's opinion about an asset rather than a property of it. Carrying it produced 434 keys where 399 are
 * correct, with 426 assets sitting in groups that disagreed with themselves. {@link #hybridComponents()} and
 * {@link #asciiCaseRisk()} are likewise out-of-key by construction, so recording them re-keys nothing.
 */
public final class NormalizedAsset {

    private String assetType;
    private String name;
    private String oid;
    private String rawOid;
    private String family;
    private String primitive;
    private Integer parameterSet;
    private String curve;
    private String mode;
    private String padding;
    private String paddingFromName;
    private String variant;
    private String familySource = "none";
    private String curveSource;
    private String oidDerivedFamily;
    private boolean oidConflict;
    private final List<String> hybridComponents = new ArrayList<>();
    private final List<String> asciiCaseRisk = new ArrayList<>();
    private final List<String> keyedCaseValues = new ArrayList<>();
    private final List<String> notes = new ArrayList<>();

    NormalizedAsset(String assetType, String name) {
        this.assetType = assetType;
        this.name = name;
    }

    /** The routed asset type, or {@code null} when the producer named one this specification does not know. */
    public String assetType() {
        return assetType;
    }

    public String name() {
        return name;
    }

    public String oid() {
        return oid;
    }

    /** The producer's own spelling, kept so an unusable arc can be reported rather than silently dropped. */
    public String rawOid() {
        return rawOid;
    }

    public String family() {
        return family;
    }

    /** Stored, indexed and filterable. Never keyed -- see the class documentation for the measurement. */
    public String primitive() {
        return primitive;
    }

    public Integer parameterSet() {
        return parameterSet;
    }

    public String curve() {
        return curve;
    }

    public String mode() {
        return mode;
    }

    public String padding() {
        return padding;
    }

    public String variant() {
        return variant;
    }

    /** How the family was decided: corroborated, producer, name, oid, or one of the subsumption outcomes. */
    public String familySource() {
        return familySource;
    }

    public String curveSource() {
        return curveSource;
    }

    public String oidDerivedFamily() {
        return oidDerivedFamily;
    }

    /** True when the arc contradicted the elected family, so its enrichment was discarded. */
    public boolean oidConflict() {
        return oidConflict;
    }

    /**
     * Which constructions a hybrid name names, when it names both a classical and a post-quantum one.
     *
     * <p>
     * The registry has no hybrid token, so a hybrid's stored family is whichever construction the grammar elects -- for
     * {@code X25519-ML-KEM-768} that is the classical half, and a readiness rule keyed on the family would read a
     * migrated asset as un-migrated. Recorded beside the row so a rule or an operator can find hybrids without waiting
     * for a vocabulary decision.
     */
    public List<String> hybridComponents() {
        return List.copyOf(hybridComponents);
    }

    /** Non-ASCII cased characters that reach the key unfolded, for the batch-scoped case-fold twin detector. */
    public List<String> asciiCaseRisk() {
        return List.copyOf(asciiCaseRisk);
    }

    /**
     * The keyed text the twin detector examines: the pre-image itself, then every inner string whose digest it carries.
     *
     * <p>
     * Detector input only. It must never reach a stored payload or a key, which is why it is excluded from the
     * provenance block below -- and it is the dictionary-attackable input itself, not a selection of the fields that
     * fed it, so the fence around the pre-image applies to this accessor in full.
     */
    public List<String> keyedCaseValues() {
        return List.copyOf(keyedCaseValues);
    }

    /** What the pipeline decided and why, in the operator's terms. Stored as JSON; adds no typed column. */
    public List<String> notes() {
        return List.copyOf(notes);
    }

    void setAssetType(String assetType) {
        this.assetType = assetType;
    }

    void setName(String name) {
        this.name = name;
    }

    void setOid(String oid) {
        this.oid = oid;
    }

    void setRawOid(String rawOid) {
        this.rawOid = rawOid;
    }

    void setFamily(String family) {
        this.family = family;
    }

    void setPrimitive(String primitive) {
        this.primitive = primitive;
    }

    void setParameterSet(Integer parameterSet) {
        this.parameterSet = parameterSet;
    }

    void setCurve(String curve) {
        this.curve = curve;
    }

    void setMode(String mode) {
        this.mode = mode;
    }

    void setPadding(String padding) {
        this.padding = padding;
    }

    String paddingFromName() {
        return paddingFromName;
    }

    void setPaddingFromName(String paddingFromName) {
        this.paddingFromName = paddingFromName;
    }

    void setVariant(String variant) {
        this.variant = variant;
    }

    void setFamilySource(String familySource) {
        this.familySource = familySource;
    }

    void setCurveSource(String curveSource) {
        this.curveSource = curveSource;
    }

    void setOidDerivedFamily(String oidDerivedFamily) {
        this.oidDerivedFamily = oidDerivedFamily;
    }

    void setOidConflict(boolean oidConflict) {
        this.oidConflict = oidConflict;
    }

    void addHybridComponents(List<String> components) {
        hybridComponents.addAll(components);
    }

    void setAsciiCaseRisk(List<String> risk) {
        asciiCaseRisk.clear();
        asciiCaseRisk.addAll(risk);
    }

    void setKeyedCaseValues(List<String> values) {
        keyedCaseValues.clear();
        keyedCaseValues.addAll(values);
    }

    void note(String note) {
        notes.add(note);
    }
}
