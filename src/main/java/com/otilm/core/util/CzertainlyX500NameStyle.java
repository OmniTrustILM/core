package com.otilm.core.util;

import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.oid.OidHandler;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;

import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Map;
import java.util.stream.Collectors;

public class CzertainlyX500NameStyle extends BCStrictStyle {

    // Kept here because of migration
    public static final CzertainlyX500NameStyle DEFAULT = new CzertainlyX500NameStyle(false);
    public static final CzertainlyX500NameStyle NORMALIZED = new CzertainlyX500NameStyle(true);

    private final boolean normalizedStyle;
    private final String delimiter;

    private final Map<String, String> oidToCodeMap;

    public CzertainlyX500NameStyle(boolean normalizedStyle) {
        this.normalizedStyle = normalizedStyle;
        this.delimiter = normalizedStyle ? "," : ", ";
        this.oidToCodeMap = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE).entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue().code()
                ));
    }

    @Override
    public String toString(X500Name x500Name) {
        StringBuilder stringBuilder = new StringBuilder();
        boolean isFirstRdn = true;
        RDN[] rdNs = x500Name.getRDNs();
        if (this.normalizedStyle) {
            Arrays.sort(rdNs, Comparator.comparing((RDN obj) -> obj.getFirst().getType().getId()).thenComparing(obj -> obj.getFirst().getValue().toString()));
        } else {
            Collections.reverse(Arrays.asList(rdNs));
        }
        for (RDN rdn : rdNs) {
            if (isFirstRdn) {
                isFirstRdn = false;
            } else {
                stringBuilder.append(this.delimiter);
            }

            appendRDN(stringBuilder, rdn);
        }

        return stringBuilder.toString();
    }

    private String getRdnCode(AttributeTypeAndValue attributeTypeAndValue) {
        ASN1ObjectIdentifier type = attributeTypeAndValue.getType();
        if (this.normalizedStyle) return type.getId();
        if (oidToCodeMap.get(type.getId()) != null) return  oidToCodeMap.get(type.getId());
        if (this.defaultSymbols.get(type) != null) return (String) this.defaultSymbols.get(type);
        return type.getId();
    }

    private void appendRDN(StringBuilder stringBuilder, RDN rdn) {
        if (rdn.isMultiValued()) {
            AttributeTypeAndValue[] attributeTypeAndValues = rdn.getTypesAndValues();
            boolean isFirst = true;

            for (int i = 0; i != attributeTypeAndValues.length; ++i) {
                if (isFirst) {
                    isFirst = false;
                } else {
                    stringBuilder.append('+');
                }
                appendTypeAndValue(stringBuilder, attributeTypeAndValues[i]);
            }
        } else if (rdn.getFirst() != null) {
            appendTypeAndValue(stringBuilder, rdn.getFirst());
        }
    }

    private void appendTypeAndValue(StringBuilder stringBuilder, AttributeTypeAndValue attributeTypeAndValue) {
        stringBuilder.append(getRdnCode(attributeTypeAndValue));
        stringBuilder.append('=');
        stringBuilder.append(attributeTypeAndValue.getValue().toString());
    }

}
