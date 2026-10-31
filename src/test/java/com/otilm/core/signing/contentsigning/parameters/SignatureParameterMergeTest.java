package com.otilm.core.signing.contentsigning.parameters;

import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.parameters.SignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.CommitmentType;
import com.otilm.api.model.common.signature.parameters.pades.HorizontalAlignment;
import com.otilm.api.model.common.signature.parameters.pades.ImageScaling;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignatureDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignaturePlacementDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesVisibleSignatureStyleDto;
import com.otilm.api.model.common.signature.parameters.pades.VerticalAlignment;
import com.otilm.core.util.builders.PadesSignatureParametersDtoBuilder;
import com.otilm.core.util.builders.PadesVisibleSignaturePlacementDtoBuilder;
import java.lang.reflect.Field;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.PadesSignatureParametersDtoBuilder.aPadesParameters;
import static com.otilm.core.util.builders.PadesVisibleSignatureDtoBuilder.aVisibleSignature;
import static com.otilm.core.util.builders.PadesVisibleSignaturePlacementDtoBuilder.aPlacement;
import static com.otilm.core.util.builders.PadesVisibleSignatureStyleDtoBuilder.aStyle;
import static org.assertj.core.api.Assertions.assertThat;

class SignatureParameterMergeTest {

    // ── Fields ───────────────────────────────────────────────────────────────

    @Nested
    class Fields {

        @Test
        void inheritsProfileValue_whenRequestOmitsTheField() {
            // given
            var profileLocation = "Prague";
            var requestedReason = "Contract approval";
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withReason("Default reason")
                    .withLocation(profileLocation)
                    .build();
            PadesSignatureParametersDto requested = aPadesParameters().withReason(requestedReason).build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested);

            // then: the request wins its own field and the profile's other field survives
            assertThat(merged.getReason()).isEqualTo(requestedReason);
            assertThat(merged.getLocation()).isEqualTo(profileLocation);
        }

        @Test
        void mutatesNeitherArgument() {
            // given
            PadesSignatureParametersDto defaults = aPadesParameters().withReason("Default reason").build();
            PadesSignatureParametersDto requested = aPadesParameters().withLocation("Prague").build();

            // when
            SignatureParameterMerge.merge(defaults, requested);

            // then
            assertThat(defaults.getLocation()).isNull();
            assertThat(requested.getReason()).isNull();
        }

        @Test
        void replacesListWholesale_whenRequestSuppliesOne() {
            // given
            var requestedRole = "Auditor";
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withClaimedRoles("Head of Legal", "Director")
                    .build();
            PadesSignatureParametersDto requested = aPadesParameters().withClaimedRoles(requestedRole).build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested);

            // then
            assertThat(merged.getClaimedRoles()).containsExactly(requestedRole);
        }

        @Test
        void carriesImageAndMediaTypeAsOneUnit_whenRequestSuppliesAnImage() {
            // given
            var requestedImage = new byte[]{3, 4};
            var requestedMediaType = "image/jpeg";
            PadesSignatureParametersDto defaults = parametersWithImage(new byte[]{1, 2}, "image/png").build();
            PadesSignatureParametersDto requested = parametersWithImage(requestedImage, requestedMediaType).build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested);

            // then
            assertThat(merged.getVisibleSignature().getImage()).containsExactly(requestedImage);
            assertThat(merged.getVisibleSignature().getImageMimeType()).isEqualTo(requestedMediaType);
        }

        @Test
        void keepsProfileImage_whenRequestSuppliesNoImage() {
            // given
            var profileImage = new byte[]{1, 2};
            var profileMediaType = "image/png";
            var requestedText = "Signed by Jane Doe";
            PadesSignatureParametersDto defaults = parametersWithImage(profileImage, profileMediaType).build();
            PadesSignatureParametersDto requested = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withText(requestedText))
                    .build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested);

            // then
            assertThat(merged.getVisibleSignature().getImage()).containsExactly(profileImage);
            assertThat(merged.getVisibleSignature().getImageMimeType()).isEqualTo(profileMediaType);
            assertThat(merged.getVisibleSignature().getText()).isEqualTo(requestedText);
        }

        @Test
        void keepsProfileList_whenRequestListIsEmpty() {
            // given — the request carries a claimed-roles list, but an empty one
            var profileRole = "Head of Legal";
            PadesSignatureParametersDto defaults = aPadesParameters().withClaimedRoles(profileRole).build();
            PadesSignatureParametersDto requested = aPadesParameters().withClaimedRoles().build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested);

            // then
            assertThat(merged.getClaimedRoles()).containsExactly(profileRole);
        }

        @Test
        void overridesEnumField_whenRequestSuppliesOne() {
            // given
            var requestedCommitment = CommitmentType.PROOF_OF_APPROVAL;
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withCommitmentType(CommitmentType.PROOF_OF_ORIGIN)
                    .build();
            PadesSignatureParametersDto requested = aPadesParameters().withCommitmentType(requestedCommitment).build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested);

            // then
            assertThat(merged.getCommitmentType()).isEqualTo(requestedCommitment);
        }

        @Test
        void addsContainer_whenProfileLacksItEntirely() {
            // given — the profile carries no visible-signature container at all
            var requestedImage = new byte[]{3, 4};
            var requestedMediaType = "image/jpeg";
            PadesSignatureParametersDto defaults = aPadesParameters().build();
            PadesSignatureParametersDto requested = parametersWithImage(requestedImage, requestedMediaType).build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested);

            // then
            assertThat(merged.getVisibleSignature().getImage()).containsExactly(requestedImage);
            assertThat(merged.getVisibleSignature().getImageMimeType()).isEqualTo(requestedMediaType);
        }
    }

    // ── Placement ────────────────────────────────────────────────────────────

    @Nested
    class Placement {

        @Test
        void mergesFieldByField_whenRequestUsesTheSameMode() {
            // given — profile coordinates, and a request naming only the page
            var requestedPage = 2;
            PadesSignatureParametersDto defaults = parametersWithPlacement(profileCoordinates()).build();
            PadesSignatureParametersDto requested = parametersWithPlacement(aPlacement().withPage(requestedPage))
                    .build();

            // when
            PadesVisibleSignaturePlacementDto merged = mergedPlacement(defaults, requested);

            // then: the box geometry survives the page override
            assertThat(merged.getPage()).isEqualTo(requestedPage);
            assertThat(merged.getOriginX()).isEqualTo(20f);
            assertThat(merged.getWidth()).isEqualTo(180f);
        }

        @Test
        void replacesPlacementWholesale_whenRequestSwitchesMode() {
            // given — the profile places by coordinates, the request by anchor
            PadesSignatureParametersDto defaults = parametersWithPlacement(profileCoordinates()).build();
            PadesSignatureParametersDto requested = parametersWithPlacement(aPlacement()
                    .withAlignmentHorizontal(HorizontalAlignment.RIGHT)
                    .withAlignmentVertical(VerticalAlignment.BOTTOM)).build();

            // when
            PadesVisibleSignaturePlacementDto merged = mergedPlacement(defaults, requested);

            // then
            assertThat(merged.getAlignmentHorizontal()).isEqualTo(HorizontalAlignment.RIGHT);
            assertThat(merged.getOriginX()).isNull();
            assertThat(merged.getWidth()).isNull();
            assertThat(merged.getPage()).isNull();
        }

        @Test
        void discardsProfileCoordinates_whenRequestNamesAField() {
            // given
            var requestedFieldId = "Signature1";
            PadesSignatureParametersDto defaults = parametersWithPlacement(profileCoordinates()).build();
            PadesSignatureParametersDto requested = parametersWithPlacement(aPlacement().withFieldId(requestedFieldId))
                    .build();

            // when
            PadesVisibleSignaturePlacementDto merged = mergedPlacement(defaults, requested);

            // then
            assertThat(merged.getFieldId()).isEqualTo(requestedFieldId);
            assertThat(merged.getOriginX()).isNull();
            assertThat(merged.getPage()).isNull();
        }

        @Test
        void takesRequestPlacement_whenProfileHasNone() {
            // given — the profile carries no visible-signature container at all
            PadesSignatureParametersDto defaults = aPadesParameters().build();
            PadesSignatureParametersDto requested = parametersWithPlacement(profileCoordinates()).build();

            // when
            PadesVisibleSignaturePlacementDto merged = mergedPlacement(defaults, requested);

            // then
            assertThat(merged.getPage()).isEqualTo(1);
            assertThat(merged.getOriginX()).isEqualTo(20f);
        }

        /**
         * Unlike {@link #takesRequestPlacement_whenProfileHasNone()}, the profile's {@code visibleSignature} exists
         * without a {@code placement}, so the placement merge itself sees no defaults.
         */
        @Test
        void takesRequestPlacement_whenProfileVisibleSignatureCarriesNone() {
            // given
            var profileText = "Signed by Jane Doe";
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withText(profileText))
                    .build();
            PadesSignatureParametersDto requested = parametersWithPlacement(profileCoordinates()).build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested);

            // then
            assertThat(merged.getVisibleSignature().getText()).isEqualTo(profileText);
            assertThat(merged.getVisibleSignature().getPlacement().getPage()).isEqualTo(1);
            assertThat(merged.getVisibleSignature().getPlacement().getOriginX()).isEqualTo(20f);
        }

        @Test
        void completesAPageOnlyProfile_whenTheRequestSuppliesCoordinates() {
            // given — a profile carrying only the page, which the coordinate and anchor modes share
            PadesSignatureParametersDto defaults = parametersWithPlacement(aPlacement().withPage(1)).build();
            PadesSignatureParametersDto requested = parametersWithPlacement(
                    aPlacement().withOriginX(20f).withOriginY(30f).withWidth(180f).withHeight(60f)).build();

            // when
            PadesVisibleSignaturePlacementDto merged = mergedPlacement(defaults, requested);

            // then
            assertThat(merged.getPage()).isEqualTo(1);
            assertThat(merged.getOriginX()).isEqualTo(20f);
            assertThat(merged.getHeight()).isEqualTo(60f);
        }

        @Test
        void completesAPageOnlyProfile_whenTheRequestAnchorsTheSignature() {
            // given
            var requestedAlignment = HorizontalAlignment.RIGHT;
            PadesSignatureParametersDto defaults = parametersWithPlacement(aPlacement().withPage(1)).build();
            PadesSignatureParametersDto requested = parametersWithPlacement(aPlacement()
                    .withAlignmentHorizontal(requestedAlignment)
                    .withAlignmentVertical(VerticalAlignment.BOTTOM)).build();

            // when
            PadesVisibleSignaturePlacementDto merged = mergedPlacement(defaults, requested);

            // then
            assertThat(merged.getPage()).isEqualTo(1);
            assertThat(merged.getAlignmentHorizontal()).isEqualTo(requestedAlignment);
        }

        /** A named field admits nothing beside itself, so the page the other modes share cannot complete it. */
        @Test
        void replacesPlacementWholesale_whenANamedFieldMeetsAPageOnlyPlacement() {
            // given
            var requestedFieldId = "Signature1";
            PadesSignatureParametersDto defaults = parametersWithPlacement(aPlacement().withPage(1)).build();
            PadesSignatureParametersDto requested = parametersWithPlacement(aPlacement().withFieldId(requestedFieldId))
                    .build();

            // when
            PadesVisibleSignaturePlacementDto merged = mergedPlacement(defaults, requested);

            // then
            assertThat(merged.getFieldId()).isEqualTo(requestedFieldId);
            assertThat(merged.getPage()).isNull();
        }

        @Test
        void replacesPlacementWholesale_whenAPageOnlyRequestMeetsANamedField() {
            // given
            var requestedPage = 2;
            PadesSignatureParametersDto defaults = parametersWithPlacement(aPlacement().withFieldId("Signature1"))
                    .build();
            PadesSignatureParametersDto requested = parametersWithPlacement(aPlacement().withPage(requestedPage))
                    .build();

            // when
            PadesVisibleSignaturePlacementDto merged = mergedPlacement(defaults, requested);

            // then
            assertThat(merged.getPage()).isEqualTo(requestedPage);
            assertThat(merged.getFieldId()).isNull();
        }

        @Test
        void keepsTheProfilesNamedField_whenTheRequestCarriesAnEmptyPlacement() {
            // given — the reason keeps the request from counting as absent, so the merge reaches the placement
            var profileFieldId = "Signature1";
            PadesSignatureParametersDto defaults = parametersWithPlacement(aPlacement().withFieldId(profileFieldId))
                    .build();
            PadesSignatureParametersDto requested = aPadesParameters()
                    .withReason("Contract approval")
                    .withVisibleSignature(aVisibleSignature().withPlacement(aPlacement()))
                    .build();

            // when
            PadesVisibleSignaturePlacementDto merged = mergedPlacement(defaults, requested);

            // then
            assertThat(merged.getFieldId()).isEqualTo(profileFieldId);
        }

        @Test
        void mergesAnchorFieldByField_whenRequestUsesTheSameMode() {
            // given
            var profilePage = 1;
            var requestedAlignment = HorizontalAlignment.RIGHT;
            PadesSignatureParametersDto defaults = parametersWithPlacement(aPlacement()
                    .withPage(profilePage)
                    .withAlignmentHorizontal(HorizontalAlignment.LEFT)
                    .withAlignmentVertical(VerticalAlignment.TOP)).build();
            PadesSignatureParametersDto requested = parametersWithPlacement(
                    aPlacement().withAlignmentHorizontal(requestedAlignment)).build();

            // when
            PadesVisibleSignaturePlacementDto merged = mergedPlacement(defaults, requested);

            // then
            assertThat(merged.getAlignmentHorizontal()).isEqualTo(requestedAlignment);
            assertThat(merged.getAlignmentVertical()).isEqualTo(VerticalAlignment.TOP);
            assertThat(merged.getPage()).isEqualTo(profilePage);
        }
    }

    // ── Style ────────────────────────────────────────────────────────────────

    @Nested
    class Style {

        @Test
        void mergesFieldByField_whenBothSidesSpeak() {
            // given
            var profileBackground = "#F5F5F5";
            var requestedTextColor = "#171717";
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature()
                            .withStyle(aStyle().withTextColor("#000000").withBackgroundColor(profileBackground)))
                    .build();
            PadesSignatureParametersDto requested = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withStyle(aStyle().withTextColor(requestedTextColor)))
                    .build();

            // when
            PadesVisibleSignatureStyleDto merged = ((PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested)).getVisibleSignature().getStyle();

            // then
            assertThat(merged.getTextColor()).isEqualTo(requestedTextColor);
            assertThat(merged.getBackgroundColor()).isEqualTo(profileBackground);
        }

        @Test
        void takesRequestStyle_whenProfileHasNone() {
            // given
            var profileText = "Signed by Jane Doe";
            var requestedDpi = 300;
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withVisible(true).withText(profileText))
                    .build();
            PadesSignatureParametersDto requested = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withStyle(aStyle().withDpi(requestedDpi)))
                    .build();

            // when
            PadesVisibleSignatureDto merged = ((PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested)).getVisibleSignature();

            // then
            assertThat(merged.getStyle().getDpi()).isEqualTo(requestedDpi);
            assertThat(merged.getText()).isEqualTo(profileText);
        }

        @Test
        void keepsProfileStyle_whenRequestOmitsIt() {
            // given
            var profileScaling = ImageScaling.ZOOM_AND_CENTER;
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withStyle(aStyle().withImageScaling(profileScaling)))
                    .build();
            PadesSignatureParametersDto requested = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withText("Signed by Jane Doe"))
                    .build();

            // when
            PadesVisibleSignatureStyleDto merged = ((PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested)).getVisibleSignature().getStyle();

            // then
            assertThat(merged.getImageScaling()).isEqualTo(profileScaling);
        }

        /** Style describes a stamp that is drawn, so it leaves with the container. */
        @Test
        void dropsStyleWithTheContainer_whenTheEffectiveVisibleIsFalse() {
            // given — a reason the merge keeps, so the assertion is about the container alone
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withReason("Contract approval")
                    .withVisibleSignature(
                            aVisibleSignature().withVisible(true).withStyle(aStyle().withTextColor("#171717")))
                    .build();
            PadesSignatureParametersDto requested = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withVisible(false))
                    .build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested);

            // then
            assertThat(merged.getVisibleSignature()).isNull();
        }
    }

    // ── Visibility ───────────────────────────────────────────────────────────

    @Nested
    class Visibility {

        @Test
        void dropsTheContainer_whenRequestSetsVisibleFalse() {
            // given — a fully drawn profile signature and a reason, and a request turning it off
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withReason("Contract approval")
                    .withVisibleSignature(aVisibleSignature()
                            .withVisible(true)
                            .withText("Signed by Jane Doe")
                            .withImage(new byte[]{1, 2}, "image/png")
                            .withPlacement(profileCoordinates()))
                    .build();
            PadesSignatureParametersDto requested = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withVisible(false))
                    .build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested);

            // then
            assertThat(merged.getVisibleSignature()).isNull();
        }

        /** The request leaves visibility unset. */
        @Test
        void dropsTheContainer_whenProfileStoresVisibleFalse() {
            // given
            var requestedReason = "Contract approval";
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(
                            aVisibleSignature().withVisible(false).withImage(new byte[]{1, 2}, "image/png"))
                    .build();
            PadesSignatureParametersDto requested = aPadesParameters().withReason(requestedReason).build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested);

            // then
            assertThat(merged.getVisibleSignature()).isNull();
            assertThat(merged.getReason()).isEqualTo(requestedReason);
        }

        @Test
        void inheritsProfileVisibility_whenRequestOmitsIt() {
            // given
            var profileText = "Signed by Jane Doe";
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withVisible(true).withText(profileText))
                    .build();
            PadesSignatureParametersDto requested = aPadesParameters().build();

            // when
            PadesVisibleSignatureDto merged = ((PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested)).getVisibleSignature();

            // then
            assertThat(merged.getVisible()).isTrue();
            assertThat(merged.getText()).isEqualTo(profileText);
        }
    }

    // ── AbsentSides ──────────────────────────────────────────────────────────

    @Nested
    class AbsentSides {

        @Test
        void copiesTheDefaults_whenThereIsNoRequest() {
            // given
            var profileReason = "Default reason";
            PadesSignatureParametersDto defaults = aPadesParameters().withReason(profileReason).build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, null);

            // then
            assertThat(merged).isNotSameAs(defaults);
            assertThat(merged.getReason()).isEqualTo(profileReason);
        }

        @Test
        void copiesTheRequest_whenThereAreNoDefaults() {
            // given
            var requestedReason = "Contract approval";
            PadesSignatureParametersDto requested = aPadesParameters().withReason(requestedReason).build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(null, requested);

            // then
            assertThat(merged).isNotSameAs(requested);
            assertThat(merged.getReason()).isEqualTo(requestedReason);
        }

        @Test
        void returnsNothing_whenNeitherSideSpeaks() {
            // given — neither a profile default nor a request

            // when / then
            assertThat(SignatureParameterMerge.merge(null, null)).isNull();
        }

        /** The permission check reads an envelope carrying only the family as touching no group; so must the merge. */
        @Test
        void treatsEmptyEnvelopeAsAbsentRequest() {
            // given
            var profileReason = "Default reason";
            PadesSignatureParametersDto defaults = aPadesParameters().withReason(profileReason).build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, aPadesParameters().build());

            // then
            assertThat(merged.getReason()).isEqualTo(profileReason);
        }

        @Test
        void returnsNothing_whenEmptyEnvelopeMeetsNoDefaults() {
            // given — an envelope supplying nothing, and no profile defaults

            // when / then
            assertThat(SignatureParameterMerge.merge(null, aPadesParameters().build())).isNull();
        }

        /**
         * Every merge path drops the container, or one profile hands the connector two different effective objects
         * depending only on whether the request carried any parameter at all.
         */
        @Test
        void dropsUndrawnContainer_whenOnlyTheProfileSpeaks() {
            // given — a reason the merge keeps, so the assertion is about the container alone
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withReason("Contract approval")
                    .withVisibleSignature(aVisibleSignature()
                            .withVisible(false)
                            .withText("Signed by Operator")
                            .withPlacement(aPlacement().withPage(1)))
                    .build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, null);

            // then
            assertThat(merged.getVisibleSignature()).isNull();
        }

        /** An empty object would otherwise hand the connector a decision the group permission check never saw. */
        @Test
        void dropsAnEmptyContainer_whenTheRequestSuppliesOnlyAnotherGroup() {
            // given
            PadesSignatureParametersDto requested = aPadesParameters()
                    .withReason("Contract approval")
                    .withVisibleSignature(aVisibleSignature())
                    .build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(null, requested);

            // then
            assertThat(merged.getVisibleSignature()).isNull();
        }

        @Test
        void dropsAnEmptyPlacement_whenTheRequestCarriesOneBesideRealContent() {
            // given
            PadesSignatureParametersDto requested = aPadesParameters()
                    .withVisibleSignature(
                            aVisibleSignature().withText("Signed by Jane Doe").withPlacement(aPlacement()))
                    .build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(null, requested);

            // then
            assertThat(merged.getVisibleSignature().getPlacement()).isNull();
        }

        @Test
        void dropsAnEmptyStyle_whenTheRequestCarriesOneBesideRealContent() {
            // given
            var requestedText = "Signed by Jane Doe";
            PadesSignatureParametersDto requested = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withText(requestedText).withStyle(aStyle()))
                    .build();

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(null, requested);

            // then
            assertThat(merged.getVisibleSignature().getText()).isEqualTo(requestedText);
            assertThat(merged.getVisibleSignature().getStyle()).isNull();
        }

        @Test
        void returnsNothing_whenTheProfileOnlySwitchesTheSignatureOff() {
            // given
            PadesSignatureParametersDto defaults = aPadesParameters()
                    .withVisibleSignature(aVisibleSignature().withVisible(false))
                    .build();

            // when / then
            assertThat(SignatureParameterMerge.merge(defaults, null)).isNull();
        }
    }

    // ── Discriminator ────────────────────────────────────────────────────────

    @Nested
    class Discriminator {

        @Test
        void keepsTheFamily_whenTheRequestCarriesAnother() throws Exception {
            // given — a request whose discriminator was forced to another family behind the setter's back
            var profileReason = "Default reason";
            var requestedLocation = "Prague";
            PadesSignatureParametersDto defaults = aPadesParameters().withReason(profileReason).build();
            PadesSignatureParametersDto requested = aPadesParameters().withLocation(requestedLocation).build();
            Field family = SignatureParametersDto.class.getDeclaredField("family");
            family.setAccessible(true);
            family.set(requested, SignatureFamily.XADES);

            // when
            PadesSignatureParametersDto merged = (PadesSignatureParametersDto) SignatureParameterMerge
                    .merge(defaults, requested);

            // then
            assertThat(merged.getFamily()).isEqualTo(SignatureFamily.PADES);
            assertThat(merged.getLocation()).isEqualTo(requestedLocation);
            assertThat(merged.getReason()).isEqualTo(profileReason);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static PadesSignatureParametersDtoBuilder parametersWithImage(byte[] image, String mimeType) {
        return aPadesParameters().withVisibleSignature(aVisibleSignature().withImage(image, mimeType));
    }

    private static PadesSignatureParametersDtoBuilder parametersWithPlacement(
            PadesVisibleSignaturePlacementDtoBuilder placement) {
        return aPadesParameters().withVisibleSignature(aVisibleSignature().withPlacement(placement));
    }

    /** The profile's box geometry, which each coordinate scenario overrides one field of. */
    private static PadesVisibleSignaturePlacementDtoBuilder profileCoordinates() {
        return aPlacement().withPage(1).withOriginX(20f).withOriginY(30f).withWidth(180f).withHeight(60f);
    }

    private static PadesVisibleSignaturePlacementDto mergedPlacement(PadesSignatureParametersDto defaults,
            PadesSignatureParametersDto requested) {
        return ((PadesSignatureParametersDto) SignatureParameterMerge.merge(defaults, requested))
                .getVisibleSignature()
                .getPlacement();
    }
}
