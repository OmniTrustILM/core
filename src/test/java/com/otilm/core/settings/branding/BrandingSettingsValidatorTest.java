package com.otilm.core.settings.branding;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.settings.BrandingSettingsUpdateDto;
import com.otilm.api.model.core.settings.BrandingTheme;
import java.util.function.BiConsumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class BrandingSettingsValidatorTest {

    private static Stream<BiConsumer<BrandingSettingsUpdateDto, String>> colorSetters() {
        return Stream
                .of(BrandingSettingsUpdateDto::setPrimaryColor, BrandingSettingsUpdateDto::setSecondaryColor,
                        BrandingSettingsUpdateDto::setTertiaryColor, BrandingSettingsUpdateDto::setBackgroundColor,
                        BrandingSettingsUpdateDto::setTextColor);
    }

    /** Every field is optional, so an operator clearing all of their branding at once must not be refused. */
    @Test
    void anEmptyUpdateIsAccepted() {
        Assertions.assertDoesNotThrow(() -> BrandingSettingsValidator.validated(new BrandingSettingsUpdateDto()));
    }

    @Test
    void aFullyPopulatedUpdateIsAccepted() {
        BrandingSettingsUpdateDto branding = new BrandingSettingsUpdateDto();
        branding.setPrimaryColor("#0073CF");
        branding.setSecondaryColor("#00a3e0");
        branding.setTertiaryColor("#7B61FF");
        branding.setBackgroundColor("#FFFFFF");
        branding.setTextColor("#171717");
        branding.setDefaultTheme(BrandingTheme.DARK);

        Assertions.assertDoesNotThrow(() -> BrandingSettingsValidator.validated(branding));
    }

    @ParameterizedTest
    @MethodSource("colorSetters")
    void everyColorAcceptsSixDigitHexInEitherCase(BiConsumer<BrandingSettingsUpdateDto, String> setter) {
        BrandingSettingsUpdateDto branding = new BrandingSettingsUpdateDto();
        setter.accept(branding, "#aB12Ef");

        Assertions.assertDoesNotThrow(() -> BrandingSettingsValidator.validated(branding));
    }

    @ParameterizedTest
    @ValueSource(strings = {"#FFF", "0073CF", "blue", "#0073CFF", "rgb(0,115,207)", ""})
    void everyColorRejectsAnythingOtherThanSixDigitHex(String candidate) {
        colorSetters().forEach(setter -> {
            BrandingSettingsUpdateDto branding = new BrandingSettingsUpdateDto();
            setter.accept(branding, candidate);

            Assertions
                    .assertThrows(ValidationException.class, () -> BrandingSettingsValidator.validated(branding),
                            "accepted invalid color " + candidate);
        });
    }

    /** The Appearance form shows the rejection against a specific row, so the message has to say which one. */
    @Test
    void aRejectedColorNamesItsField() {
        BrandingSettingsUpdateDto branding = new BrandingSettingsUpdateDto();
        branding.setBackgroundColor("chartreuse");

        String message = Assertions
                .assertThrows(ValidationException.class, () -> BrandingSettingsValidator.validated(branding))
                .getMessage();

        Assertions.assertTrue(message.contains("backgroundColor"), message);
    }

    /**
     * A missing body never gets past Bean Validation on the controller path, but the service is reachable without it,
     * and the accessors would dereference the null before anything named the problem.
     */
    @Test
    void aMissingUpdateIsRefusedRatherThanDereferenced() {
        Assertions.assertThrows(ValidationException.class, () -> BrandingSettingsValidator.validated(null));
    }

    @Test
    void logosAreValidatedThroughTheSameUpdate() {
        BrandingSettingsUpdateDto branding = new BrandingSettingsUpdateDto();
        branding.setDarkLogo("data:image/jpeg;base64,/9j/4AAQ");

        String message = Assertions
                .assertThrows(ValidationException.class, () -> BrandingSettingsValidator.validated(branding))
                .getMessage();

        Assertions.assertTrue(message.contains("darkLogo"), message);
    }
}
