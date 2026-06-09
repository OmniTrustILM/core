package com.otilm.core.util;

import com.otilm.api.model.core.certificate.CertificateValidationCheck;
import com.otilm.api.model.core.certificate.CertificateValidationCheckDto;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;

public class MetaDefinitions {
	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	public static String serialize(Map<String, Object> metaData) {
		try {
			return OBJECT_MAPPER.writeValueAsString(metaData);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public static Map<String, Object> deserialize(String metaJson) {
		if (metaJson == null || metaJson.isEmpty()) {
			return new HashMap<>();
		}
		try {
			return OBJECT_MAPPER.readValue(metaJson, new TypeReference<>() {
			});
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public static String serializeValidation(Map<String, CertificateValidationCheckDto> metaData) {
		try {
			return OBJECT_MAPPER.writeValueAsString(metaData);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public static Map<CertificateValidationCheck, CertificateValidationCheckDto> deserializeValidation(String metaJson) {
		if (metaJson == null || metaJson.isEmpty()) {
			return new EnumMap<>(CertificateValidationCheck.class);
		}
		try {
			return OBJECT_MAPPER.readValue(metaJson, new TypeReference<>() {
			});
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public static String serializeArrayString(List<String> metaData) {
		try {
			return OBJECT_MAPPER.writeValueAsString(metaData);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public static List<String> deserializeArrayString(String metaJson) {
		if (metaJson == null || metaJson.isEmpty()) {
			return new ArrayList<>();
		}
		try {
			return OBJECT_MAPPER.readValue(metaJson, new TypeReference<>() {
			});
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

}
