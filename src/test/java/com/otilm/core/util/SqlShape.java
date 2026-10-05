package com.otilm.core.util;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Questions a test asks about the SQL a listing rendered. Text shape rather than plans: the shape is deterministic on
 * IT-sized data, a plan is not.
 */
public final class SqlShape {

    /** A row limit that closes a parenthesised subquery; the page's own window ends the statement instead. */
    private static final Pattern SUBQUERY_ROW_LIMIT = Pattern.compile("fetch first (\\?|\\d+) rows only\\)");

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

    /**
     * Whether the outer query groups by the root's uuid, the only grouping these listings apply. Hibernate may render
     * the grouping by select-list position ({@code group by 1}), so any GROUP BY outside parentheses counts; a derived
     * table or a subquery grouping its own rows does not.
     */
    public static boolean groupsByRootUuid(String sql) {
        return outerQuery(sql).contains(" group by ");
    }

    public static boolean hasDerivedJoin(String sql) {
        return sql.contains("join (select");
    }

    /**
     * Whether a sort key is a scalar subquery fetching the first row, the per-row form. The limit is rendered as a bind
     * parameter, so either form of it counts.
     */
    public static boolean hasScalarSortSubquery(String sql) {
        return SUBQUERY_ROW_LIMIT.matcher(sql).find();
    }

    /** Whether {@code table} is joined into the statement, as opposed to read inside an EXISTS subquery. */
    public static boolean joinsTable(String sql, String table) {
        return Pattern.compile("join \\(?(\\w+\\.)?\"?" + Pattern.quote(table) + "\"?\\b").matcher(sql).find();
    }

    public static boolean countsDistinct(String sql) {
        return sql.startsWith("select count(distinct");
    }

    /** The statement without its parenthesised parts: what the outer query alone says. */
    private static String outerQuery(String sql) {
        StringBuilder outer = new StringBuilder();
        int depth = 0;
        for (char c : sql.toCharArray()) {
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
            } else if (depth == 0) {
                outer.append(c);
            }
        }
        return outer.toString();
    }
}
