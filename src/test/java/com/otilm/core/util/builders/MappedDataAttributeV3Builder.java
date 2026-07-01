package com.otilm.core.util.builders;

import com.otilm.api.model.common.attribute.common.constraint.RegexpAttributeConstraint;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.mapping.ExtensionMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.MappedField;
import com.otilm.api.model.common.attribute.v3.mapping.ObjectType;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.SanMappedField;
import com.otilm.api.model.core.certificate.GeneralNameType;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds a {@link DataAttributeV3} carrying an X.509 {@link FieldMapping}.
 * Defaults produce a minimal valid optional STRING attribute named "attr" with no mapped fields.
 * Call {@code mappingRdn/mappingSan} to add targets.
 */
public final class MappedDataAttributeV3Builder {

    private String name = "attr";
    private boolean required = false;
    private String regex = null;
    private final List<MappedField> fields = new ArrayList<>();

    public static MappedDataAttributeV3Builder aMappedDataAttribute() {
        return new MappedDataAttributeV3Builder();
    }

    public MappedDataAttributeV3Builder withName(String name) {
        this.name = name;
        return this;
    }

    public MappedDataAttributeV3Builder required() {
        this.required = true;
        return this;
    }

    public MappedDataAttributeV3Builder withRegex(String regex) {
        this.regex = regex;
        return this;
    }

    public MappedDataAttributeV3Builder mappingRdn(String code) {
        RdnMappedField field = new RdnMappedField();
        field.setRdn(code);
        fields.add(field);
        return this;
    }

    public MappedDataAttributeV3Builder mappingSan(GeneralNameType type) {
        SanMappedField field = new SanMappedField();
        field.setGeneralNameType(type);
        fields.add(field);
        return this;
    }

    public MappedDataAttributeV3Builder mappingExtension(String oid) {
        ExtensionMappedField field = new ExtensionMappedField();
        field.setExtensionOid(oid);
        fields.add(field);
        return this;
    }

    public DataAttributeV3 build() {
        DataAttributeV3 attribute = new DataAttributeV3();
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel(name);
        properties.setRequired(required);
        attribute.setProperties(properties);
        if (regex != null) {
            RegexpAttributeConstraint constraint = new RegexpAttributeConstraint();
            constraint.setData(regex);
            attribute.setConstraints(List.of(constraint));
        }
        FieldMapping mapping = new FieldMapping();
        mapping.setObjectType(ObjectType.X509_CERTIFICATE);
        mapping.setFields(new ArrayList<>(fields));
        attribute.setFieldMapping(mapping);
        return attribute;
    }
}
