package com.otilm.core.settings.branding;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.settings.BrandingSettingsUpdateDto;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Validates a branding update before it reaches the settings table.
 *
 * <p>
 * The contract already carries the same colour and logo rules as Bean Validation constraints, and the controller
 * applies them. They are repeated here because the service is also reachable without passing through the controller,
 * and because a malformed value that gets stored is served on every page render — including the login page, to callers
 * who have not authenticated.
 */
public final class BrandingSettingsValidator {

    private static final Pattern COLOR = Pattern.compile(BrandingSettingsUpdateDto.COLOR_REGEX);

    private static final Map<String, Function<BrandingSettingsUpdateDto, String>> COLORS = colorAccessors();

    private BrandingSettingsValidator() {
    }

    private static Map<String, Function<BrandingSettingsUpdateDto, String>> colorAccessors() {
        Map<String, Function<BrandingSettingsUpdateDto, String>> accessors = new LinkedHashMap<>();
        accessors.put("primaryColor", BrandingSettingsUpdateDto::getPrimaryColor);
        accessors.put("secondaryColor", BrandingSettingsUpdateDto::getSecondaryColor);
        accessors.put("tertiaryColor", BrandingSettingsUpdateDto::getTertiaryColor);
        accessors.put("backgroundColor", BrandingSettingsUpdateDto::getBackgroundColor);
        accessors.put("textColor", BrandingSettingsUpdateDto::getTextColor);
        return Map.copyOf(accessors);
    }

    /**
     * Validates a branding update and returns the form of it that may be stored: identical to the submitted one except
     * that SVG logos come back sanitized. Returning a copy rather than editing the caller's object keeps the submitted
     * request intact for logging, and makes it impossible to store an unsanitized logo by forgetting to reassign.
     */
    public static BrandingSettingsUpdateDto validated(BrandingSettingsUpdateDto branding) {
        // Bean Validation rejects a missing body on the controller path, but the service is also reachable directly,
        // and a caller that gets there with nothing to apply has made a mistake worth naming rather than a null
        // dereference deep inside an accessor.
        if (branding == null) {
            throw new ValidationException("Branding settings must be provided.");
        }

        COLORS.forEach((field, accessor) -> validateColor(field, accessor.apply(branding)));

        BrandingSettingsUpdateDto stored = new BrandingSettingsUpdateDto();
        stored.setPrimaryColor(branding.getPrimaryColor());
        stored.setSecondaryColor(branding.getSecondaryColor());
        stored.setTertiaryColor(branding.getTertiaryColor());
        stored.setBackgroundColor(branding.getBackgroundColor());
        stored.setTextColor(branding.getTextColor());
        stored.setDefaultTheme(branding.getDefaultTheme());
        stored.setLightLogo(BrandingLogoValidator.validateAndSanitize("lightLogo", branding.getLightLogo()));
        stored.setDarkLogo(BrandingLogoValidator.validateAndSanitize("darkLogo", branding.getDarkLogo()));
        return stored;
    }

    private static void validateColor(String field, String value) {
        if (value != null && !COLOR.matcher(value).matches()) {
            throw new ValidationException(
                    "Branding color '%s' is not a six-digit hexadecimal value prefixed with '#'.".formatted(field));
        }
    }
}
