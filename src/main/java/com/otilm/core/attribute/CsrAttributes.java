package com.otilm.core.attribute;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.constraint.BaseAttributeConstraint;
import com.otilm.api.model.common.attribute.common.constraint.RegexpAttributeConstraint;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.FieldType;
import com.otilm.api.model.common.attribute.v3.mapping.ObjectType;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.api.model.core.oid.SystemOid;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class CsrAttributes {

    public static final String COMMON_NAME_UUID = "9abaeba0-973d-11ed-a8fc-0242ac120002";
    public static final String ORGANIZATION_UNIT_UUID = "9abaef60-973d-11ed-a8fc-0242ac120002";
    public static final String ORGANIZATION_UUID = "9abaf0be-973d-11ed-a8fc-0242ac120002";
    public static final String LOCALITY_UUID = "9abaf208-973d-11ed-a8fc-0242ac120002";
    public static final String STATE_UUID = "9abaf33e-973d-11ed-a8fc-0242ac120002";
    public static final String COUNTRY_UUID = "9abaf488-973d-11ed-a8fc-0242ac120002";

    public static final String COMMON_NAME_ATTRIBUTE_NAME = "commonName";
    public static final String ORGANIZATION_UNIT_ATTRIBUTE_NAME = "organizationalUnit";
    public static final String ORGANIZATION_ATTRIBUTE_NAME = "organization";
    public static final String LOCALITY_ATTRIBUTE_NAME = "locality";
    public static final String STATE_ATTRIBUTE_NAME = "state";
    public static final String COUNTRY_ATTRIBUTE_NAME = "country";

    public static final String COMMON_NAME_ATTRIBUTE_LABEL = "Common Name";
    public static final String ORGANIZATION_UNIT_ATTRIBUTE_LABEL = "Organizational Unit";
    public static final String ORGANIZATION_ATTRIBUTE_LABEL = "Organization";
    public static final String LOCALITY_ATTRIBUTE_LABEL = "Locality";
    public static final String STATE_ATTRIBUTE_LABEL = "State";
    public static final String COUNTRY_ATTRIBUTE_LABEL = "Country";

    private CsrAttributes() {}

    @CoreAttributeDefinitions
    public static List<DataAttributeV3> csrAttributesAsDataAttributesV3() {
        return List.of(
                commonNameAttribute(),
                organizationalUnitAttribute(),
                organizationAttribute(),
                localityAttribute(),
                stateAttribute(),
                countryAttribute()
        );
    }

    public static DataAttributeV3 commonNameAttribute() {
        List<BaseAttributeConstraint<?>> constraints = List.of(new RegexpAttributeConstraint(
                "Common Name Validation",
                "Common Name must not exceed 64 characters",
                "^.{0,64}$"
        ));
        return build(
                COMMON_NAME_UUID,
                COMMON_NAME_ATTRIBUTE_NAME,
                "Common Name for the certificate",
                COMMON_NAME_ATTRIBUTE_LABEL,
                true,
                constraints,
                rdnMapping(SystemOid.COMMON_NAME.getCode())
        );
    }

    public static DataAttributeV3 organizationalUnitAttribute() {
        return build(
                ORGANIZATION_UNIT_UUID,
                ORGANIZATION_UNIT_ATTRIBUTE_NAME,
                ORGANIZATION_UNIT_ATTRIBUTE_LABEL,
                ORGANIZATION_UNIT_ATTRIBUTE_LABEL,
                false,
                null,
                rdnMapping(SystemOid.ORGANIZATION_UNIT.getCode())
        );
    }

    public static DataAttributeV3 organizationAttribute() {
        return build(
                ORGANIZATION_UUID,
                ORGANIZATION_ATTRIBUTE_NAME,
                ORGANIZATION_ATTRIBUTE_LABEL,
                ORGANIZATION_ATTRIBUTE_LABEL,
                false,
                null,
                rdnMapping(SystemOid.ORGANIZATION.getCode())
        );
    }

    public static DataAttributeV3 localityAttribute() {
        return build(
                LOCALITY_UUID,
                LOCALITY_ATTRIBUTE_NAME,
                LOCALITY_ATTRIBUTE_LABEL,
                LOCALITY_ATTRIBUTE_LABEL,
                false,
                null,
                rdnMapping(SystemOid.LOCALITY.getCode())
        );
    }

    public static DataAttributeV3 stateAttribute() {
        return build(
                STATE_UUID,
                STATE_ATTRIBUTE_NAME,
                STATE_ATTRIBUTE_LABEL,
                STATE_ATTRIBUTE_LABEL,
                false,
                null,
                rdnMapping(SystemOid.STATE.getCode())
        );
    }

    public static DataAttributeV3 countryAttribute() {
        List<BaseAttributeConstraint<?>> constraints = List.of(new RegexpAttributeConstraint(
                "Country Validation",
                "Country Can contain only 2 upper case letters",
                "^[A-Z]{2}$"
        ));
        return build(
                COUNTRY_UUID,
                COUNTRY_ATTRIBUTE_NAME,
                COUNTRY_ATTRIBUTE_LABEL,
                COUNTRY_ATTRIBUTE_LABEL,
                false,
                constraints,
                rdnMapping(SystemOid.COUNTRY.getCode())
        );
    }

    private static FieldMapping rdnMapping(String rdnCode) {
        RdnMappedField field = new RdnMappedField();
        field.setFieldType(FieldType.RDN);
        field.setRdn(rdnCode);

        FieldMapping fm = new FieldMapping();
        fm.setObjectType(ObjectType.X509_CERTIFICATE);
        fm.setFields(List.of(field));
        return fm;
    }

    private static DataAttributeV3 build(String uuid, String name, String description, String label,
                                         boolean required, List<BaseAttributeConstraint<?>> constraints,
                                         FieldMapping fieldMapping) {
        DataAttributeV3 attr = new DataAttributeV3();
        attr.setUuid(uuid);
        attr.setName(name);
        attr.setDescription(description);
        attr.setType(AttributeType.DATA);
        attr.setContentType(AttributeContentType.STRING);
        attr.setConstraints(constraints);
        attr.setFieldMapping(fieldMapping);

        DataAttributeProperties props = new DataAttributeProperties();
        props.setLabel(label);
        props.setRequired(required);
        props.setReadOnly(false);
        props.setList(false);
        props.setVisible(true);
        props.setMultiSelect(false);
        attr.setProperties(props);

        return attr;
    }
}
