package com.otilm.core.util.builders;

import com.otilm.api.model.common.attribute.common.constraint.RegexpAttributeConstraint;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.mapping.ExtendedKeyUsageMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.ExtensionMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.FieldType;
import com.otilm.api.model.common.attribute.v3.mapping.KeyUsageMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.MappedField;
import com.otilm.api.model.common.attribute.v3.mapping.ObjectType;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.SanMappedField;
import com.otilm.api.model.core.certificate.GeneralNameType;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds a {@link DataAttributeV3} carrying an X.509 {@link FieldMapping}. Defaults produce a minimal valid optional
 * STRING attribute named "attr" with no mapped fields. Call {@code mappingRdn/mappingSan} to add targets.
 */
public final class MappedDataAttributeV3Builder {

    private String name = "attr";
    private boolean required = false;
    private boolean list = false;
    private boolean readOnly = false;
    private boolean extensibleList = false;
    private String regex = null;
    private final List<String> content = new ArrayList<>();
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

    public MappedDataAttributeV3Builder list() {
        this.list = true;
        return this;
    }

    public MappedDataAttributeV3Builder readOnly() {
        this.readOnly = true;
        return this;
    }

    public MappedDataAttributeV3Builder extensibleList() {
        this.extensibleList = true;
        return this;
    }

    public MappedDataAttributeV3Builder withContent(String... items) {
        this.content.addAll(List.of(items));
        return this;
    }

    public MappedDataAttributeV3Builder mappingKeyUsage() {
        KeyUsageMappedField field = new KeyUsageMappedField();
        field.setFieldType(FieldType.KEY_USAGE);
        fields.add(field);
        return this;
    }

    public MappedDataAttributeV3Builder mappingExtendedKeyUsage() {
        ExtendedKeyUsageMappedField field = new ExtendedKeyUsageMappedField();
        field.setFieldType(FieldType.EXTENDED_KEY_USAGE);
        fields.add(field);
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

    public MappedDataAttributeV3Builder mappingOtherName(String otherNameOid) {
        SanMappedField field = new SanMappedField();
        field.setGeneralNameType(GeneralNameType.OTHER_NAME);
        field.setOtherNameOid(otherNameOid);
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
        properties.setList(list);
        properties.setReadOnly(readOnly);
        properties.setExtensibleList(extensibleList);
        attribute.setProperties(properties);
        if (!content.isEmpty()) {
            List<BaseAttributeContentV3<?>> items = new ArrayList<>();
            for (String item : content) {
                items.add(new StringAttributeContentV3(item));
            }
            attribute.setContent(items);
        }
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
