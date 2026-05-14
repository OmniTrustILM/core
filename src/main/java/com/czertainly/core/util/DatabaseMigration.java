package com.czertainly.core.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;

/**
 * Helper class for calculating checksums of files.
 * And for storing the checksums of the Java-based migrations.
 * Inspired by <a href="https://github.com/zaunerc/flyway-checksum-tool">flyway-checksum-tool</a>
 */
public class DatabaseMigration {

    /**
     * Calculates the checksum of a file.
     *
     * @param filePath The path to the file.
     * @return The checksum of the file.
     */
    public static int calculateChecksum(String filePath) throws IOException {
        final File file = new File(filePath);
        final CRC32 crc32 = new CRC32();

        try (FileReader fileReader = new FileReader(file); BufferedReader bufferedReader = new BufferedReader(fileReader, 4096)) {
            String line;
            boolean firstLineProcessed = false;
            while ((line = bufferedReader.readLine()) != null) {
                if(!firstLineProcessed) {
                    line = filterBomFromString(line);
                    firstLineProcessed = true;
                }
                String trimmed = trimLineBreak(line);
                crc32.update(trimmed != null ? trimmed.getBytes(StandardCharsets.UTF_8) : new byte[0]);
            }
        } catch (IOException e) {
            System.out.printf("Error while trying to read file %s: %s%n", filePath, e.getMessage());
            throw e;
        }

        return (int) crc32.getValue();
    }

    /**
     * Stores the checksum of a Java-based migration.
     */
    @SuppressWarnings("java:S115")
    public enum JavaMigrationChecksums {
        V202206151000__AttributeChanges(595685930),
        V202209211100__Access_Control(-2127987777),
        V202211031400__AttributeV2Changes(-691194104),
        V202211141030__AttributeV2TablesAndMigration(-1479676999, true),
        V202301311500__PublicKeyMigration(-761670493),
        V202303211718__Scep_Roles(-285333526),
        V202303230830__AttributeContentJsonMigration(1077049851),
        V202308050825__UpdateAcmeScepRolesPermissions(414709752),
        V202311071500__IssuerAndSubjectDnMigration(-1352440028, true),
        V202402171510__UpdateAndOptimizeAttributesModelMigration(-1671016899, true),
        V202404021100__CreateCmpUserAndPermissions(-264892945),
        V202404120915__AssignObjectsOwnerAndMultipleGroupsMigration(-305812276),
        V202408231055__DuplicateCertificates(-1714171989),
        V202411141900__CreateLocalhostUserAndPermissions(1923994081),
        V202501281511__LinkKeysToCertificates(-1169157739),
        V202501281641__DuplicateCertificateContents(492594371),
        V202505211440__ChangeConditionValueForNotAfterAndNotBefore(-529789813),
        V202506131400__NotificationSettingsToEventSettings(1970609093),
        V202507311051__MigrateToComplianceProfilesV2(404080942, true),
        V202508130940__CertificateRelations(-1359523966),
        V202508261555__EnumCollectionsColumnsBitmask(-1617046736),
        V202508281320__UniqueCryptographicKeyItemFingerprint(2020026258),
        V202509041555__CertificateRequestEntityBitmask(1876867908),
        V202509191412__LogRecordsRefactor(79840308),
        V202604011901__BackfillExtendedKeyUsageCritical(-1512779938);

        private final int checksum;

        private final boolean isAltered;

        JavaMigrationChecksums(int checksum) {
            this(checksum, false);
        }

        JavaMigrationChecksums(int checksum, boolean isAltered) {
            this.checksum = checksum;
            this.isAltered = isAltered;
        }

        public int getChecksum() {
            return checksum;
        }

        public boolean isAltered() {
            return isAltered;
        }
    }

    private static final char BOM = '\ufeff';

    /**
     * Determine if this char is a UTF-8 Byte Order Mark
     * @param c The char to check
     * @return Whether this char is a UTF-8 Byte Order Mark
     */
    public static boolean isBom(char c) {
        return c == BOM;
    }

    /**
     * Removes the UTF-8 Byte Order Mark from the start of a string if present.
     * @param s The string
     * @return The string without a Byte Order Mark at the start
     */
    public static String filterBomFromString(String s) {
        if (s.isEmpty()) {
            return s;
        }

        if (isBom(s.charAt(0))) {
            return s.substring(1);
        }

        return s;
    }

    /**
     * Trim the trailing linebreak (if any) from this string.
     *
     * @param str The string.
     * @return The string without trailing linebreak.
     */
    public static String trimLineBreak(String str) {
        if (!hasLength(str)) {
            return str;
        }
        StringBuilder buf = new StringBuilder(str);
        while (buf.length() > 0 && isLineBreakCharacter(buf.charAt(buf.length() - 1))) {
            buf.deleteCharAt(buf.length() - 1);
        }
        return buf.toString();
    }

    /**
     * Checks whether this string is not {@code null} and not <i>empty</i>.
     *
     * @param str The string to check.
     * @return {@code true} if it has content, {@code false} if it is {@code null} or blank.
     */
    public static boolean hasLength(String str) {
        return str != null && str.length() > 0;
    }

    /**
     * Checks whether this character is a linebreak character.
     *
     * @param ch The character
     * @return {@code true} if it is, {@code false} if not.
     */
    private static boolean isLineBreakCharacter(char ch) {
        return '\n' == ch || '\r' == ch;
    }
}
