package com.otilm.core.service.impl;

import com.otilm.api.model.core.audit.ExportResultDto;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.csv.CsvGenerator;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;


@Component
public class ExportProcessor {

    private static final DateTimeFormatter EXPORT_DATE_TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH-mm-ss");
    private static final CsvMapper CSV_MAPPER = new CsvMapper();

    static {
        CSV_MAPPER.findAndRegisterModules();
        CSV_MAPPER.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        CSV_MAPPER.enable(CsvGenerator.Feature.ESCAPE_QUOTE_CHAR_WITH_ESCAPE_CHAR);
    }

    @Value("${export.encoding:UTF-8}")
    private String encoding;

    @Value("${export.separator:,}")
    private Character separator;

    @Value("${export.lineEnding:\r\n}")
    private String lineEnding;

    @Value("${export.header:true}")
    private Boolean isHeaderIncluded;

    @Value("${export.zip:true}")
    private Boolean isZipped;

    public <T> ExportResultDto generateExport(String fileNamePrefix, List<T> data) {
        ExportResultDto result = new ExportResultDto();

        String fileNameDateTime = LocalDateTime.now().format(EXPORT_DATE_TIME_FORMAT);
        String fileName = "%s_%s.csv".formatted(fileNamePrefix, fileNameDateTime);

        if (data == null || data.isEmpty()) {
            result.setFileContent(new byte[0]);
            return result;
        }

        try (ByteArrayOutputStream os = new ByteArrayOutputStream();
             OutputStreamWriter osWriter = new OutputStreamWriter(os, encoding)) {

            CsvSchema schema = CSV_MAPPER.schemaFor(data.get(0).getClass())
                    .withColumnSeparator(separator)
                    .withLineSeparator(lineEnding)
                    .withUseHeader(isHeaderIncluded)
                    .withQuoteChar('"')
                    .withEscapeChar('\\');

            ObjectWriter writer = CSV_MAPPER.writer()
                    .with(schema);

            writer.writeValue(osWriter, data);

            if (isZipped) {
                try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
                     ZipOutputStream zos = new ZipOutputStream(bos)) {
                    zos.putNextEntry(new ZipEntry(fileName));
                    zos.write(os.toByteArray());
                    zos.closeEntry();
                    zos.finish();
                    zos.flush();

                    result.setFileName("%s_%s.zip".formatted(fileNamePrefix, fileNameDateTime));
                    result.setFileContent(bos.toByteArray());
                }
            } else {
                result.setFileName(fileName);
                result.setFileContent(os.toByteArray());
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return result;
    }
}
