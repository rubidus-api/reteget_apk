package org.reteget.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The settings file ReteGet exports and imports, to move them to another phone or keep a copy:
 * the options, the presets, and the signing keys seen so far for each app (so the signing-key
 * continuity check carries over). The download queue is not included; it belongs to the device.
 *
 * <p><b>Format.</b> The rete family's settings file (the same shape as ReteClock's), written in the
 * subset of INI and TOML that both read with the same meaning: UTF-8 without a BOM, whole-line
 * {@code #} comments, {@code [section]} and {@code key = value} with names of {@code [a-z0-9_-]},
 * each key once per section and none above the first section, and values that are
 * {@code true}/{@code false}, an integer, or a double-quoted string whose only escapes are
 * {@code \\} and {@code \"}.
 *
 * <pre>
 * # reteget settings 1
 * [options]
 * built_in_tls = false
 * auto_upgrade = true
 *
 * [preset-1]
 * name = "ReteGet"
 * url = "https://github.com/rubidus-api/reteget_apk/releases/download/v{1}/reteget-{1}.apk"
 * index = "https://api.github.com/repos/rubidus-api/reteget_apk/releases?per_page=20"
 * version = "0.3.1"
 *
 * [signer-1]
 * package = "com.reteclock"
 * sha256 = "90:44:6B:..."
 * author = "reteclock"
 * </pre>
 *
 * <p><b>Reading is forgiving</b>, as in ReteClock: a file edited by hand may have changed case,
 * lost its quotes, gained {@code ;} comments or a {@code :} instead of {@code =}, or Windows line
 * endings; none of that is an error. What cannot be understood is reported line by line in
 * {@link #complaints} instead of guessed at.
 */
public final class SettingsBundle {

    public static final String HEADER = "# reteget settings 1";
    public static final String FILE_PREFIX = "reteget-settings";
    public static final String FILE_SUFFIX = ".ini";

    public String appVersion = "";
    /** Null when the file does not say. */
    public Boolean builtInTls;
    /** Null when the file does not say. */
    public Boolean autoUpgrade;
    public final List<PresetItem> presets = new ArrayList<PresetItem>();
    /** package name -> { sha256 fingerprint, author } */
    public final Map<String, String[]> signers = new LinkedHashMap<String, String[]>();
    /** One sentence per line that was skipped while reading; empty when all was understood. */
    public final List<String> complaints = new ArrayList<String>();

    // ------------------------------------------------------------------ writing

    public String write() {
        StringBuilder out = new StringBuilder();
        out.append(HEADER).append('\n');
        out.append("# One key to a line; lines beginning with # are notes.\n");
        out.append("# Text is in double quotes, where \\\\ is a backslash and \\\" a quote.\n");
        if (appVersion.length() > 0) {
            out.append("# Written by ReteGet ").append(clean(appVersion)).append(".\n");
        }
        out.append("\n[options]\n");
        if (builtInTls != null) {
            out.append("built_in_tls = ").append(builtInTls.booleanValue()).append('\n');
        }
        if (autoUpgrade != null) {
            out.append("auto_upgrade = ").append(autoUpgrade.booleanValue()).append('\n');
        }
        for (int i = 0; i < presets.size(); i++) {
            PresetItem p = presets.get(i);
            out.append("\n[preset-").append(i + 1).append("]\n");
            text(out, "name", p.name);
            text(out, "url", p.url);
            text(out, "index", p.index);
            text(out, "file", p.lastFileName);
            if (p.lastFileSize >= 0) out.append("size = ").append(p.lastFileSize).append('\n');
            text(out, "version", p.lastVersion);
            if (p.lastDownloadedAt > 0) out.append("time = ").append(p.lastDownloadedAt).append('\n');
            text(out, "sha256", p.lastSha256);
            text(out, "signer", p.lastSigFingerprint);
            text(out, "author", p.lastAuthor);
        }
        int n = 0;
        for (Map.Entry<String, String[]> e : signers.entrySet()) {
            out.append("\n[signer-").append(++n).append("]\n");
            text(out, "package", e.getKey());
            text(out, "sha256", e.getValue()[0]);
            text(out, "author", e.getValue()[1]);
        }
        return out.toString();
    }

    private static void text(StringBuilder out, String key, String value) {
        if (value == null || value.length() == 0) return;
        out.append(key).append(" = ").append(quote(value)).append('\n');
    }

    /** A double-quoted string with only the escapes both formats agree on. */
    static String quote(String value) {
        String v = clean(value);
        StringBuilder sb = new StringBuilder(v.length() + 2).append('"');
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '\\' || c == '"') sb.append('\\');
            sb.append(c);
        }
        return sb.append('"').toString();
    }

    /** Control characters have no escape in the subset, so they are dropped (none belong here). */
    private static String clean(String v) {
        StringBuilder sb = new StringBuilder(v.length());
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c >= 0x20 && c != 0x7f) sb.append(c);
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ reading

    /** Reads a settings file, forgiving what can be forgiven and listing what cannot. */
    public static SettingsBundle parse(String text) {
        SettingsBundle b = new SettingsBundle();
        if (text == null) {
            throw new IllegalArgumentException("empty file");
        }
        if (text.length() > 0 && text.charAt(0) == '﻿') text = text.substring(1);
        String section = null;
        Map<String, String> record = null;
        String recordKind = null;
        boolean sawAnything = false;
        String[] lines = text.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].replace("\r", "").trim();
            if (line.length() == 0 || line.charAt(0) == '#' || line.charAt(0) == ';') {
                continue;
            }
            if (line.charAt(0) == '[') {
                int close = line.indexOf(']');
                if (close < 0) {
                    b.complaints.add("line " + (i + 1) + ": a section name without ]");
                    section = "";
                    continue;
                }
                b.finishRecord(recordKind, record);
                section = line.substring(1, close).trim().toLowerCase(Locale.US);
                if (section.startsWith("preset")) {
                    recordKind = "preset";
                } else if (section.startsWith("signer")) {
                    recordKind = "signer";
                } else {
                    recordKind = null;
                }
                record = recordKind == null ? null : new LinkedHashMap<String, String>();
                if (recordKind == null && !"options".equals(section)) {
                    b.complaints.add("line " + (i + 1) + ": no section called [" + shorten(section) + "]");
                }
                sawAnything = true;
                continue;
            }
            int cut = separator(line);
            if (cut < 0) {
                b.complaints.add("line " + (i + 1) + ": no = in \"" + shorten(line) + "\"");
                continue;
            }
            String key = line.substring(0, cut).trim().toLowerCase(Locale.US);
            String value = unquote(line.substring(cut + 1).trim());
            sawAnything = true;
            if (section == null) {
                b.complaints.add("line " + (i + 1) + ": " + key + " stands above the first section");
            } else if (record != null) {
                if (!knownKey(recordKind, key)) {
                    b.complaints.add("line " + (i + 1) + ": a " + recordKind + " has no \"" + shorten(key) + "\"");
                } else {
                    record.put(key, value);
                }
            } else if ("options".equals(section)) {
                if ("built_in_tls".equals(key) || "auto_upgrade".equals(key)) {
                    Boolean v = bool(value);
                    if (v == null) {
                        b.complaints.add("line " + (i + 1) + ": " + key + " cannot be \"" + shorten(value) + "\"");
                    } else if ("built_in_tls".equals(key)) {
                        b.builtInTls = v;
                    } else {
                        b.autoUpgrade = v;
                    }
                } else {
                    b.complaints.add("line " + (i + 1) + ": this version has no option called \"" + shorten(key) + "\"");
                }
            }
        }
        b.finishRecord(recordKind, record);
        if (!sawAnything || (!text.startsWith("# reteget") && b.presets.isEmpty() && b.signers.isEmpty()
                && b.builtInTls == null && b.autoUpgrade == null)) {
            throw new IllegalArgumentException("not a ReteGet settings file");
        }
        return b;
    }

    private void finishRecord(String kind, Map<String, String> r) {
        if (kind == null || r == null) return;
        if ("preset".equals(kind)) {
            String url = r.get("url");
            if (url == null || url.trim().length() == 0) {
                complaints.add("a preset without a url was skipped");
                return;
            }
            PresetItem p = new PresetItem(orEmpty(r.get("name")), url, r.get("file"),
                    number(r.get("size"), -1), r.get("version"), number(r.get("time"), 0),
                    r.get("sha256"), r.get("signer"), r.get("author"));
            p.index = orEmpty(r.get("index")).trim();
            if (!presets.contains(p)) presets.add(p);
        } else {
            String pkg = r.get("package");
            String fp = r.get("sha256");
            if (pkg == null || fp == null || pkg.length() == 0 || fp.length() == 0) {
                complaints.add("a signer without package or sha256 was skipped");
                return;
            }
            signers.put(pkg, new String[] { fp, orEmpty(r.get("author")) });
        }
    }

    private static boolean knownKey(String kind, String key) {
        String[] keys = "preset".equals(kind)
                ? new String[] { "name", "url", "index", "file", "size", "version", "time", "sha256", "signer", "author" }
                : new String[] { "package", "sha256", "author" };
        for (String k : keys) {
            if (k.equals(key)) return true;
        }
        return false;
    }

    /** First '=' or ':' — whichever comes first — so "url: https://x" and "url = https://x" both read. */
    private static int separator(String line) {
        int eq = line.indexOf('=');
        int colon = line.indexOf(':');
        if (eq < 0) return colon;
        if (colon < 0) return eq;
        return Math.min(eq, colon);
    }

    /** A quoted value loses its quotes and escapes; a bare one (hand-edited, INI style) is kept. */
    static String unquote(String v) {
        if (v.length() >= 2 && v.charAt(0) == '"' && v.charAt(v.length() - 1) == '"') {
            StringBuilder sb = new StringBuilder(v.length());
            for (int i = 1; i < v.length() - 1; i++) {
                char c = v.charAt(i);
                if (c == '\\' && i + 1 < v.length() - 1) {
                    char n = v.charAt(i + 1);
                    if (n == '\\' || n == '"') {
                        sb.append(n);
                        i++;
                        continue;
                    }
                }
                sb.append(c);
            }
            return sb.toString();
        }
        return v;
    }

    private static Boolean bool(String v) {
        String l = v.toLowerCase(Locale.US);
        if ("true".equals(l) || "yes".equals(l) || "on".equals(l) || "1".equals(l)) return Boolean.TRUE;
        if ("false".equals(l) || "no".equals(l) || "off".equals(l) || "0".equals(l)) return Boolean.FALSE;
        return null;
    }

    private static long number(String v, long def) {
        if (v == null) return def;
        try {
            return Long.parseLong(v.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static String orEmpty(String v) {
        return v == null ? "" : v;
    }

    private static String shorten(String t) {
        return t.length() <= 40 ? t : t.substring(0, 37) + "...";
    }

    // ------------------------------------------------------------------ merging

    /** Result of merging imported presets into the current list. */
    public static final class Merge {
        public final List<PresetItem> presets = new ArrayList<PresetItem>();
        public int added;
        public int updated;
    }

    /**
     * Imported presets are matched by URL: a match takes the imported name and record, a new URL
     * is added at the end, and presets that are only on this phone stay as they are.
     */
    public static Merge mergePresets(List<PresetItem> current, List<PresetItem> imported) {
        Merge r = new Merge();
        r.presets.addAll(current);
        for (PresetItem in : imported) {
            int i = r.presets.indexOf(in);
            if (i >= 0) {
                PresetItem old = r.presets.get(i);
                if (!old.toJson().equals(in.toJson())) {
                    r.presets.set(i, in);
                    r.updated++;
                }
            } else {
                r.presets.add(in);
                r.added++;
            }
        }
        return r;
    }
}
