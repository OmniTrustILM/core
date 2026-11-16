package com.otilm.core.dao.converter;

import com.otilm.api.model.common.signature.SignatureFamily;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/** Stores a signature family as its code. A connector may declare codes beyond the well-known families. */
@Converter
public class SignatureFamilyAttributeConverter implements AttributeConverter<SignatureFamily, String> {

    @Override
    public String convertToDatabaseColumn(SignatureFamily family) {
        return family == null ? null : family.code();
    }

    @Override
    public SignatureFamily convertToEntityAttribute(String code) {
        return code == null ? null : new SignatureFamily(code);
    }
}
