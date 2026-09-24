package org.reteget.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses and resolves URL templates with placeholders such as {1}, {2}, {version}.
 */
public final class UrlTemplate {
    private static final Pattern TOKEN_PATTERN = Pattern.compile("\\{([A-Za-z0-9_]+)\\}");

    private final String template;
    private final List<String> placeholders;

    public UrlTemplate(String template) {
        this.template = template == null ? "" : template.trim();
        this.placeholders = extractPlaceholders(this.template);
    }

    public String getTemplate() {
        return template;
    }

    public boolean hasPlaceholders() {
        return !placeholders.isEmpty();
    }

    public List<String> getPlaceholders() {
        return Collections.unmodifiableList(placeholders);
    }

    /**
     * Resolves the template with the provided key-value mappings.
     */
    public String resolve(Map<String, String> values) {
        if (!hasPlaceholders() || values == null) {
            return template;
        }

        StringBuffer sb = new StringBuffer();
        Matcher matcher = TOKEN_PATTERN.matcher(template);
        while (matcher.find()) {
            String token = matcher.group(1);
            String val = values.get(token);
            if (val == null) {
                val = ""; // empty if unspecified
            }
            matcher.appendReplacement(sb, Matcher.quoteReplacement(val));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * Resolves placeholders in order using an array or list of values.
     * e.g. for {1} and {2}, args[0] replaces {1}, args[1] replaces {2}.
     */
    public String resolvePositional(String... args) {
        if (!hasPlaceholders() || args == null || args.length == 0) {
            return template;
        }

        StringBuffer sb = new StringBuffer();
        Matcher matcher = TOKEN_PATTERN.matcher(template);
        int idx = 0;
        while (matcher.find()) {
            String replacement = idx < args.length ? (args[idx] != null ? args[idx] : "") : "";
            matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            idx++;
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private static List<String> extractPlaceholders(String text) {
        List<String> list = new ArrayList<String>();
        Matcher matcher = TOKEN_PATTERN.matcher(text);
        while (matcher.find()) {
            String token = matcher.group(1);
            if (!list.contains(token)) {
                list.add(token);
            }
        }
        return list;
    }
}
