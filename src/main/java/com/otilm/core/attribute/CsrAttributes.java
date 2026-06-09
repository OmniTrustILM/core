package com.otilm.core.attribute;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.constraint.BaseAttributeConstraint;
import com.otilm.api.model.common.attribute.common.constraint.RegexpAttributeConstraint;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class CsrAttributes {

    /**
     * UUID of the CSR Attributes
     */
    public static final String COMMON_NAME_UUID = "9abaeba0-973d-11ed-a8fc-0242ac120002";
    public static final String ORGANIZATION_UNIT_UUID = "9abaef60-973d-11ed-a8fc-0242ac120002";
    public static final String ORGANIZATION_UUID = "9abaf0be-973d-11ed-a8fc-0242ac120002";
    public static final String LOCALITY_UUID = "9abaf208-973d-11ed-a8fc-0242ac120002";
    public static final String STATE_UUID = "9abaf33e-973d-11ed-a8fc-0242ac120002";
    public static final String COUNTRY_UUID = "9abaf488-973d-11ed-a8fc-0242ac120002";

    /**
     * Name of the CSR Attributes
     */
    public static final String COMMON_NAME_ATTRIBUTE_NAME = "commonName";
    public static final String ORGANIZATION_UNIT_ATTRIBUTE_NAME = "organizationalUnit";
    public static final String ORGANIZATION_ATTRIBUTE_NAME = "organization";
    public static final String LOCALITY_ATTRIBUTE_NAME = "locality";
    public static final String STATE_ATTRIBUTE_NAME = "state";
    public static final String COUNTRY_ATTRIBUTE_NAME = "country";


    /**
     * Label of the CSR Attributes
     */
    public static final String COMMON_NAME_ATTRIBUTE_LABEL = "Common Name";
    public static final String ORGANIZATION_UNIT_ATTRIBUTE_LABEL = "Organizational Unit";
    public static final String ORGANIZATION_ATTRIBUTE_LABEL = "Organization";
    public static final String LOCALITY_ATTRIBUTE_LABEL = "Locality";
    public static final String STATE_ATTRIBUTE_LABEL = "State";
    public static final String COUNTRY_ATTRIBUTE_LABEL = "Country";

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private CsrAttributes() {}

    /**
     * Function to get the list of attributes for generating the CSR
     *
     * @return List of attributes for generating the CSR
     */
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

    /**
     * Common Name Attribute Generation
     *
     * @return Common Name Attribute Definition
     */
    public static DataAttributeV2 commonNameAttribute() {
        List<BaseAttributeConstraint<?>> constraints = List.of(new RegexpAttributeConstraint(
                "Common Name Validation",
                "Common Name must not exceed 64 characters",
                "^.{0,64}$"
        ));
        return attributeCoder(
                COMMON_NAME_UUID,
                COMMON_NAME_ATTRIBUTE_NAME,
                "Common Name for the certificate",
                COMMON_NAME_ATTRIBUTE_LABEL,
                true,
                constraints
        );
    }


    /**
     * Organizational Unit Attribute Generation
     *
     * @return Organizational Unit Attribute Definition
     */
    public static DataAttributeV2 organizationalUnitAttribute() {
        return attributeCoder(
                ORGANIZATION_UNIT_UUID,
                ORGANIZATION_UNIT_ATTRIBUTE_NAME,
                ORGANIZATION_UNIT_ATTRIBUTE_LABEL,
                ORGANIZATION_UNIT_ATTRIBUTE_LABEL,
                false,
                null
        );
    }

    /**
     * Organization Attribute Generation
     *
     * @return Organization Attribute Definition
     */
    public static DataAttributeV2 organizationAttribute() {
        return attributeCoder(
                ORGANIZATION_UUID,
                ORGANIZATION_ATTRIBUTE_NAME,
                ORGANIZATION_ATTRIBUTE_LABEL,
                ORGANIZATION_ATTRIBUTE_LABEL,
                false,
                null
        );
    }

    /**
     * Locality Attribute Generation
     *
     * @return Locality  Attribute Definition
     */
    public static DataAttributeV2 localityAttribute() {
        return attributeCoder(
                LOCALITY_UUID,
                LOCALITY_ATTRIBUTE_NAME,
                LOCALITY_ATTRIBUTE_LABEL,
                LOCALITY_ATTRIBUTE_LABEL,
                false,
                null
        );
    }

    /**
     * State Attribute Generation
     *
     * @return State Attribute Definition
     */
    public static DataAttributeV2 stateAttribute() {
        return attributeCoder(
                STATE_UUID,
                STATE_ATTRIBUTE_NAME,
                STATE_ATTRIBUTE_LABEL,
                STATE_ATTRIBUTE_LABEL,
                false,
                null
        );
    }

    /**
     * Country Attribute Generation
     *
     * @return Country Attribute Definition
     */
    public static DataAttributeV2 countryAttribute() {

        List<BaseAttributeConstraint<?>> constraints = List.of(new RegexpAttributeConstraint(
                "Country Validation",
                "Country Can contain only 2 upper case letters",
                "^[A-Z]{2}$"
        ));

        return attributeCoder(
                COUNTRY_UUID,
                COUNTRY_ATTRIBUTE_NAME,
                COUNTRY_ATTRIBUTE_LABEL,
                COUNTRY_ATTRIBUTE_LABEL,
                false,
                constraints
        );
    }


    private static DataAttributeV2 attributeCoder(String uuid, String name,
                                                  String description, String label,
                                                  boolean required, List<BaseAttributeConstraint<?>> constraints) {
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(uuid);
        attribute.setName(name);
        attribute.setDescription(description);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setConstraints(constraints);
        attribute.setProperties(propertyCoder(
                label,
                required
        ));
        return attribute;
    }

    /**
     * Function to get the data attribute properties
     *
     * @param label    Label for the attribute
     * @param required If the attribute is required or not
     * @return Data attribute properties
     */
    private static DataAttributeProperties propertyCoder(String label, boolean required) {
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setRequired(required);
        properties.setReadOnly(false);
        properties.setList(false);
        properties.setVisible(true);
        properties.setLabel(label);
        properties.setMultiSelect(false);
        return properties;
    }
}
