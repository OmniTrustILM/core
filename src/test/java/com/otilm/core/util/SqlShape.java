package com.otilm.core.util;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Questions a test asks about the SQL a listing rendered. Text shape rather than plans: the shape is deterministic on
 * IT-sized data, a plan is not.
 */
public final class SqlShape {

    private static final Pattern GROUP_BY_ROOT_UUID = Pattern.compile("group by \\w+\\.uuid\\b");

    private SqlShape() {
    }

    /** The uuid page query: the statement that windows its rows. */
    public static String pageQuery(List<String> statements) {
        return statements
                .stream()
                .filter(sql -> sql.contains(" offset ") && sql.contains(" fetch first "))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no paged statement among " + statements));
    }

    /** The listing's total: the statement that counts. */
    public static String countQuery(List<String> statements) {
        return statements
                .stream()
                .filter(sql -> sql.startsWith("select count("))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no count statement among " + statements));
    }

    /** Whether the outer query groups by the root's uuid. A derived table grouping by its own column does not count. */
    public static boolean groupsByRootUuid(String sql) {
        return GROUP_BY_ROOT_UUID.matcher(sql).find();
    }

    public static boolean hasDerivedJoin(String sql) {
        return sql.contains("join (select");
    }

    /** Whether a sort key is still a scalar subquery fetching the first row, the per-row form. */
    public static boolean hasScalarSortSubquery(String sql) {
        return sql.contains("fetch first 1 rows only");
    }

    /** Whether {@code table} is joined into the statement, as opposed to read inside an EXISTS subquery. */
    public static boolean joinsTable(String sql, String table) {
        return Pattern.compile("join \\(?(\\w+\\.)?\"?" + Pattern.quote(table) + "\"?\\b").matcher(sql).find();
    }

    public static boolean countsDistinct(String sql) {
        return sql.startsWith("select count(distinct");
    }
}
