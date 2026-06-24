package com.otilm.core.attribute;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.constraint.BaseAttributeConstraint;
import com.otilm.api.model.common.attribute.common.constraint.RegexpAttributeConstraint;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.FieldType;
import com.otilm.api.model.common.attribute.v3.mapping.ObjectType;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.api.model.core.oid.SystemOid;

import java.util.List;

/**
 * V3 default CSR request-attribute set. Re-expresses the six legacy subject fields
 * as {@link DataAttributeV3} with explicit {@link FieldMapping}, so the platform can
 * project attribute values directly into the X.509 subject DN without parsing a
 * flat string.
 *
 * <p>UUIDs match {@link CsrAttributes} intentionally: request attributes submitted
 * with the v2 UUIDs are compatible with these v3 definitions.
 */
public class CsrRequestAttributes {

    private CsrRequestAttributes() {}

    @CoreAttributeDefinitions
    public static List<BaseAttribute> csrAttributes() {
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
                CsrAttributes.COMMON_NAME_UUID,
                CsrAttributes.COMMON_NAME_ATTRIBUTE_NAME,
                "Common Name for the certificate",
                CsrAttributes.COMMON_NAME_ATTRIBUTE_LABEL,
                true,
                constraints,
                rdnMapping(SystemOid.COMMON_NAME.getCode())
        );
    }

    public static DataAttributeV3 organizationalUnitAttribute() {
        return build(
                CsrAttributes.ORGANIZATION_UNIT_UUID,
                CsrAttributes.ORGANIZATION_UNIT_ATTRIBUTE_NAME,
                CsrAttributes.ORGANIZATION_UNIT_ATTRIBUTE_LABEL,
                CsrAttributes.ORGANIZATION_UNIT_ATTRIBUTE_LABEL,
                false,
                null,
                rdnMapping(SystemOid.ORGANIZATION_UNIT.getCode())
        );
    }

    public static DataAttributeV3 organizationAttribute() {
        return build(
                CsrAttributes.ORGANIZATION_UUID,
                CsrAttributes.ORGANIZATION_ATTRIBUTE_NAME,
                CsrAttributes.ORGANIZATION_ATTRIBUTE_LABEL,
                CsrAttributes.ORGANIZATION_ATTRIBUTE_LABEL,
                false,
                null,
                rdnMapping(SystemOid.ORGANIZATION.getCode())
        );
    }

    public static DataAttributeV3 localityAttribute() {
        return build(
                CsrAttributes.LOCALITY_UUID,
                CsrAttributes.LOCALITY_ATTRIBUTE_NAME,
                CsrAttributes.LOCALITY_ATTRIBUTE_LABEL,
                CsrAttributes.LOCALITY_ATTRIBUTE_LABEL,
                false,
                null,
                rdnMapping(SystemOid.LOCALITY.getCode())
        );
    }

    public static DataAttributeV3 stateAttribute() {
        return build(
                CsrAttributes.STATE_UUID,
                CsrAttributes.STATE_ATTRIBUTE_NAME,
                CsrAttributes.STATE_ATTRIBUTE_LABEL,
                CsrAttributes.STATE_ATTRIBUTE_LABEL,
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
                CsrAttributes.COUNTRY_UUID,
                CsrAttributes.COUNTRY_ATTRIBUTE_NAME,
                CsrAttributes.COUNTRY_ATTRIBUTE_LABEL,
                CsrAttributes.COUNTRY_ATTRIBUTE_LABEL,
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
