package org.reteget.apk;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.StrictMode;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import org.reteget.core.ApkSignatureVerifier;
import org.reteget.core.ChecksumVerifier;
import org.reteget.core.DownloadEngine;
import org.reteget.core.DownloadQueue;
import org.reteget.core.DownloadTask;
import org.reteget.core.IndexMatcher;
import org.reteget.core.PresetItem;
import org.reteget.core.SettingsBundle;
import org.reteget.core.TlsHelper;
import org.reteget.core.UrlTemplate;

import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MainActivity extends Activity {

    private static final String PREFS_NAME = "reteget_prefs";
    private static final String KEY_PRESETS = "saved_presets";
    private static final String KEY_QUEUE = "download_queue";
    private static final String PREF_PRESETS_VERSION = "presets_version";

    private ScrollView scrollView;
    private EditText editUrl;
    private LinearLayout layoutVariables;
    private LinearLayout variablesFields;
    private TextView txtResolvedPreview;

    private EditText editExpectedChecksum;
    private Button btnClearChecksum;
    private CheckBox chkInsecureSsl;
    private CheckBox chkPureTls;
    private CheckBox chkAutoUpgrade;

    private Button btnDownload;
    private Button btnCancel;
    private ProgressBar progressBar;
    private TextView txtProgressDetails;
    private TextView txtStatus;

    private LinearLayout layoutChecksumResult;
    private TextView txtChecksumResult;
    private Button btnCopyHash;
    private Button btnVerifyHash;
    private Button btnInstall;

    // Signature verification UI & state
    private LinearLayout layoutSignatureResult;
    private TextView txtSignatureResult;
    private Button btnCopyCert;
    private ApkSignatureVerifier.VerificationResult lastSignatureResult;
    private boolean hasSignatureMismatch = false;

    // Bottom presets section
    private Button btnAddPreset;
    private TextView txtNoPresets;
    private LinearLayout layoutPresetsList;
    private LinearLayout layoutPresetBatch;
    private Button btnPresetSelectAll;
    private Button btnDeleteSelected;

    private List<PresetItem> presetList = new ArrayList<PresetItem>();
    private Map<String, EditText> variableInputs = new HashMap<String, EditText>();
    private UrlTemplate currentTemplate;

    /** Process-wide, so downloads continue across screen rotation and activity restarts. */
    private static DownloadQueue sQueue;
    private LinearLayout layoutQueueSection;
    private LinearLayout layoutQueueList;
    private Button btnQueueClear;
    private Button btnQueueDeleteSelected;
    private Button btnQueueSelectAll;
    private int queueCount;
    private final java.util.Set<Long> selectedQueueIds = new java.util.HashSet<Long>();
    private File lastDownloadedFile;
    private String lastComputedSha256 = null;
    private boolean hasChecksumMismatch = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Bypass FileUriExposedException on Android 7.0+ (API 24+)
        disableStrictModeFileUriExposure();

        try {
            DownloadEngine.setAppVersion(getPackageManager().getPackageInfo(getPackageName(), 0).versionName);
        } catch (Exception ignored) {
        }

        // Initialize TLS 1.2 and bundled modern Root CAs
        initTlsCerts();

        setContentView(R.layout.activity_main);

        bindViews();
        // The URL watcher creates the template fields that setupPresets() fills in.
        setupUrlWatcher();
        setupUrlButtons();
        setupPresets();
        setupSettingsTransfer();
        setupChecksumControls();
        setupDownloadControls();
        setupInstallControl();
        setupQueue();
    }

    /**
     * The system Download folder (Environment.DIRECTORY_DOWNLOADS, "/mnt/sdcard/Download" on
     * Android 2.3, where "sdcard" is the shared storage even on phones without a card slot).
     * When shared storage is missing, unmounted or read-only (e.g. mounted on a PC over USB),
     * files go to this app's private "downloads" folder instead, opened for reading so the
     * package installer can still read an APK.
     */
    private File chooseDownloadDir() {
        if (Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState())) {
            File dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            if (dir != null && (dir.isDirectory() || dir.mkdirs()) && dir.canWrite()) {
                return dir;
            }
        }
        File dir = new File(getFilesDir(), "downloads");
        dir.mkdirs();
        getFilesDir().setExecutable(true, false);
        dir.setExecutable(true, false);
        dir.setReadable(true, false);
        return dir;
    }

    private boolean isPrivateDownload(File f) {
        return f.getAbsolutePath().startsWith(getFilesDir().getAbsolutePath());
    }

    private void disableStrictModeFileUriExposure() {
        try {
            Method m = StrictMode.class.getMethod("disableDeathOnFileUriExposure");
            m.invoke(null);
        } catch (Exception ignored) {
            try {
                StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder().build());
            } catch (Exception ignored2) {}
        }
    }

    private void initTlsCerts() {
        InputStream is = null;
        try {
            is = getResources().openRawResource(R.raw.trusted_roots);
        } catch (Exception ignored) {}
        TlsHelper.init(is);
    }

    private void bindViews() {
        scrollView = (ScrollView) findViewById(R.id.scroll_view);
        editUrl = (EditText) findViewById(R.id.edit_url);
        layoutVariables = (LinearLayout) findViewById(R.id.layout_variables);
        variablesFields = (LinearLayout) findViewById(R.id.variables_fields);
        txtResolvedPreview = (TextView) findViewById(R.id.txt_resolved_preview);

        editExpectedChecksum = (EditText) findViewById(R.id.edit_expected_checksum);
        btnClearChecksum = (Button) findViewById(R.id.btn_clear_checksum);
        chkInsecureSsl = (CheckBox) findViewById(R.id.chk_insecure_ssl);
        chkPureTls = (CheckBox) findViewById(R.id.chk_pure_tls);
        final SharedPreferences spTls = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        chkPureTls.setChecked(spTls.getBoolean("pref_pure_tls", false));
        chkPureTls.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit().putBoolean("pref_pure_tls", isChecked).commit();
            }
        });
        chkAutoUpgrade = (CheckBox) findViewById(R.id.chk_auto_upgrade);
        chkAutoUpgrade.setChecked(spTls.getBoolean("pref_auto_upgrade", true));
        chkAutoUpgrade.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                getSharedPreferences(PREFS_NAME, MODE_PRIVATE).edit().putBoolean("pref_auto_upgrade", isChecked).commit();
            }
        });

        btnDownload = (Button) findViewById(R.id.btn_download);
        btnCancel = (Button) findViewById(R.id.btn_cancel);
        layoutQueueSection = (LinearLayout) findViewById(R.id.layout_queue_section);
        layoutQueueList = (LinearLayout) findViewById(R.id.layout_queue_list);
        btnQueueClear = (Button) findViewById(R.id.btn_queue_clear);
        btnQueueDeleteSelected = (Button) findViewById(R.id.btn_queue_delete_selected);
        btnQueueSelectAll = (Button) findViewById(R.id.btn_queue_select_all);
        progressBar = (ProgressBar) findViewById(R.id.progress_bar);
        txtProgressDetails = (TextView) findViewById(R.id.txt_progress_details);
        txtStatus = (TextView) findViewById(R.id.txt_status);

        layoutChecksumResult = (LinearLayout) findViewById(R.id.layout_checksum_result);
        txtChecksumResult = (TextView) findViewById(R.id.txt_checksum_result);
        btnCopyHash = (Button) findViewById(R.id.btn_copy_hash);
        btnVerifyHash = (Button) findViewById(R.id.btn_verify_hash);
        btnInstall = (Button) findViewById(R.id.btn_install);

        layoutSignatureResult = (LinearLayout) findViewById(R.id.layout_signature_result);
        txtSignatureResult = (TextView) findViewById(R.id.txt_signature_result);
        btnCopyCert = (Button) findViewById(R.id.btn_copy_cert);

        btnCopyCert.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (lastSignatureResult != null && lastSignatureResult.currentCert != null) {
                    copyToClipboard(lastSignatureResult.currentCert.sha256Fingerprint);
                    Toast.makeText(MainActivity.this, R.string.toast_cert_copied, Toast.LENGTH_SHORT).show();
                }
            }
        });

        btnAddPreset = (Button) findViewById(R.id.btn_add_preset);
        txtNoPresets = (TextView) findViewById(R.id.txt_no_presets);
        layoutPresetsList = (LinearLayout) findViewById(R.id.layout_presets_list);
        layoutPresetBatch = (LinearLayout) findViewById(R.id.layout_preset_batch);
        btnPresetSelectAll = (Button) findViewById(R.id.btn_preset_select_all);
        btnDeleteSelected = (Button) findViewById(R.id.btn_delete_selected);
    }

    private void setupPresets() {
        loadPresets();
        renderPresets();
        if (!presetList.isEmpty() && editUrl.getText().toString().trim().isEmpty()) {
            PresetItem initial = presetList.get(0);
            selectAndLoadPreset(initial, false);
        }

        btnAddPreset.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                final String url = editUrl.getText().toString().trim();
                if (url.isEmpty()) {
                    Toast.makeText(MainActivity.this, "URL is empty", Toast.LENGTH_SHORT).show();
                    return;
                }

                String defaultName = "";
                if (lastDownloadedFile != null && lastDownloadedFile.exists()) {
                    defaultName = lastDownloadedFile.getName();
                } else {
                    int lastSlash = url.lastIndexOf('/');
                    if (lastSlash >= 0 && lastSlash < url.length() - 1) {
                        defaultName = url.substring(lastSlash + 1);
                    }
                }

                final EditText inputName = new EditText(MainActivity.this);
                inputName.setText(defaultName);
                if (defaultName.length() > 0) {
                    inputName.setSelection(0, defaultName.length());
                }

                new AlertDialog.Builder(MainActivity.this)
                        .setTitle(R.string.dialog_add_preset_title)
                        .setMessage(R.string.dialog_add_preset_msg)
                        .setView(inputName)
                        .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                String name = inputName.getText().toString().trim();
                                saveNewPreset(name, url);
                            }
                        })
                        .setNegativeButton(android.R.string.cancel, null)
                        .show();
            }
        });

        btnPresetSelectAll.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Select all; when everything is already selected, the same button clears it.
                boolean all = !presetList.isEmpty();
                for (PresetItem p : presetList) all &= p.isSelected;
                for (PresetItem p : presetList) p.isSelected = !all;
                renderPresets();
            }
        });

        btnDeleteSelected.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                final List<PresetItem> toDelete = new ArrayList<PresetItem>();
                for (PresetItem p : presetList) {
                    if (p.isSelected) {
                        toDelete.add(p);
                    }
                }
                if (toDelete.isEmpty()) return;

                new AlertDialog.Builder(MainActivity.this)
                        .setTitle(R.string.dialog_delete_batch_title)
                        .setMessage(getString(R.string.dialog_delete_batch_msg, toDelete.size()))
                        .setPositiveButton(R.string.btn_delete, new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                presetList.removeAll(toDelete);
                                savePresets();
                                renderPresets();
                                Toast.makeText(MainActivity.this,
                                        getString(R.string.toast_presets_deleted, toDelete.size()),
                                        Toast.LENGTH_SHORT).show();
                            }
                        })
                        .setNegativeButton(android.R.string.cancel, null)
                        .show();
            }
        });
    }

    private void renderPresets() {
        layoutPresetsList.removeAllViews();
        if (presetList.isEmpty()) {
            txtNoPresets.setVisibility(View.VISIBLE);
            layoutPresetBatch.setVisibility(View.GONE);
            return;
        }
        txtNoPresets.setVisibility(View.GONE);
        layoutPresetBatch.setVisibility(View.VISIBLE);

        updateBatchSelectionState();

        LayoutInflater inflater = LayoutInflater.from(this);
        for (int i = 0; i < presetList.size(); i++) {
            final int index = i;
            final PresetItem item = presetList.get(i);
            View row = inflater.inflate(R.layout.item_preset, layoutPresetsList, false);

            CheckBox chk = (CheckBox) row.findViewById(R.id.chk_preset_select);
            chk.setChecked(item.isSelected);
            chk.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                    item.isSelected = isChecked;
                    updateBatchSelectionState();
                }
            });

            // Name / URL / record, as one paragraph that wraps across the full width.
            TextView body = (TextView) row.findViewById(R.id.txt_preset_body);
            android.text.SpannableStringBuilder sb = new android.text.SpannableStringBuilder();
            String name = item.getDisplayName();
            sb.append(name);
            sb.setSpan(new android.text.style.StyleSpan(android.graphics.Typeface.BOLD), 0, name.length(), 0);
            sb.setSpan(new android.text.style.ForegroundColorSpan(0xFF1A237E), 0, name.length(), 0);
            sb.setSpan(new android.text.style.RelativeSizeSpan(1.15f), 0, name.length(), 0);
            sb.append("  /  ");
            int urlStart = sb.length();
            sb.append(item.url);
            sb.setSpan(new android.text.style.ForegroundColorSpan(0xFF0277BD), urlStart, sb.length(), 0);
            if (item.hasIndex()) {
                sb.append("  /  ").append(getString(R.string.preset_index_label)).append(' ');
                int indexStart = sb.length();
                sb.append(item.index.trim());
                sb.setSpan(new android.text.style.ForegroundColorSpan(0xFF2E7D32), indexStart, sb.length(), 0);
            }
            String meta = item.getMetadataSummary();
            if (meta != null && meta.length() > 0) {
                sb.append("  /  ").append(meta.replace("\n", " · "));
            }
            body.setText(sb);

            body.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    selectAndLoadPreset(item, true);
                }
            });
            // Press and hold a preset to change its name (title) and URL, same as Edit.
            body.setOnLongClickListener(new View.OnLongClickListener() {
                @Override
                public boolean onLongClick(View v) {
                    promptEditPresetDialog(item);
                    return true;
                }
            });

            if (item.hasIndex()) {
                View latest = row.findViewById(R.id.btn_latest);
                latest.setVisibility(View.VISIBLE);
                latest.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        downloadLatest(item);
                    }
                });
            }

            row.findViewById(R.id.btn_use).setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    selectAndLoadPreset(item, true);
                }
            });

            row.findViewById(R.id.btn_edit).setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    promptEditPresetDialog(item);
                }
            });

            TextView btnMoveUp = (TextView) row.findViewById(R.id.btn_move_up);
            if (index == 0) {
                disableAction(btnMoveUp);
            } else {
                btnMoveUp.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        PresetItem prev = presetList.set(index - 1, item);
                        presetList.set(index, prev);
                        savePresets();
                        renderPresets();
                    }
                });
            }

            TextView btnMoveDown = (TextView) row.findViewById(R.id.btn_move_down);
            if (index == presetList.size() - 1) {
                disableAction(btnMoveDown);
            } else {
                btnMoveDown.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        PresetItem next = presetList.set(index + 1, item);
                        presetList.set(index, next);
                        savePresets();
                        renderPresets();
                    }
                });
            }

            row.findViewById(R.id.btn_delete).setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    promptDeleteSinglePresetDialog(item, index);
                }
            });

            layoutPresetsList.addView(row);
        }
    }

    private static void disableAction(TextView action) {
        action.setEnabled(false);
        action.setClickable(false);
        action.setFocusable(false);
        action.setTextColor(0xFFCFD8DC);
    }

    private void updateBatchSelectionState() {
        int selectedCount = 0;
        for (PresetItem p : presetList) {
            if (p.isSelected) selectedCount++;
        }
        btnDeleteSelected.setText(getString(R.string.btn_delete_selected, selectedCount));
        btnDeleteSelected.setEnabled(selectedCount > 0);
        boolean all = selectedCount > 0 && selectedCount == presetList.size();
        btnPresetSelectAll.setText(all ? R.string.btn_select_none : R.string.btn_select_all);
    }

    private void selectAndLoadPreset(PresetItem item, boolean showToast) {
        editUrl.setText(item.url);
        editUrl.setSelection(item.url.length());
        if (item.lastVersion != null && !item.lastVersion.isEmpty()) {
            for (Map.Entry<String, EditText> entry : variableInputs.entrySet()) {
                entry.getValue().setText(item.lastVersion);
                entry.getValue().setSelection(item.lastVersion.length());
            }
        }
        scrollView.smoothScrollTo(0, 0);
        if (showToast) {
            Toast.makeText(MainActivity.this, R.string.toast_preset_loaded, Toast.LENGTH_SHORT).show();
        }
    }

    /** Labels in a dialog: the app theme's text is dark, but the (pre-Holo) dialog frame is dark. */
    private static final int DIALOG_LABEL = 0xFFCCCCCC;

    private void promptEditPresetDialog(final PresetItem item) {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);

        TextView lblName = new TextView(this);
        lblName.setText(R.string.dialog_edit_preset_name_label);
        lblName.setTextColor(DIALOG_LABEL);
        layout.addView(lblName);

        final EditText inputName = new EditText(this);
        inputName.setHint(R.string.dialog_edit_preset_name_hint);
        inputName.setText(item.name != null ? item.name : "");
        layout.addView(inputName);

        TextView lblUrl = new TextView(this);
        lblUrl.setText(R.string.dialog_edit_preset_url_label);
        lblUrl.setTextColor(DIALOG_LABEL);
        lblUrl.setPadding(0, pad / 2, 0, 0);
        layout.addView(lblUrl);

        final EditText inputUrl = new EditText(this);
        inputUrl.setHint(R.string.dialog_edit_preset_url_hint);
        inputUrl.setText(item.url != null ? item.url : "");
        layout.addView(inputUrl);

        TextView lblIndex = new TextView(this);
        lblIndex.setText(R.string.dialog_edit_preset_index_label);
        lblIndex.setTextColor(DIALOG_LABEL);
        lblIndex.setPadding(0, pad / 2, 0, 0);
        layout.addView(lblIndex);

        final EditText inputIndex = new EditText(this);
        inputIndex.setHint(R.string.dialog_edit_preset_index_hint);
        inputIndex.setText(item.index != null ? item.index : "");
        layout.addView(inputIndex);

        new AlertDialog.Builder(this)
                .setTitle(R.string.dialog_edit_preset_title)
                .setView(layout)
                .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        String newName = inputName.getText().toString().trim();
                        String newUrl = inputUrl.getText().toString().trim();
                        if (!newUrl.isEmpty()) {
                            item.name = newName;
                            item.url = newUrl;
                            item.index = inputIndex.getText().toString().trim();
                            savePresets();
                            renderPresets();
                            Toast.makeText(MainActivity.this, R.string.toast_preset_updated, Toast.LENGTH_SHORT).show();
                        }
                    }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void promptDeleteSinglePresetDialog(final PresetItem item, final int index) {
        new AlertDialog.Builder(this)
                .setTitle(R.string.dialog_delete_preset_title)
                .setMessage(getString(R.string.dialog_delete_preset_msg, item.url))
                .setPositiveButton(R.string.btn_delete, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        if (index >= 0 && index < presetList.size()) {
                            presetList.remove(index);
                            savePresets();
                            renderPresets();
                            Toast.makeText(MainActivity.this, R.string.toast_preset_removed, Toast.LENGTH_SHORT).show();
                        }
                    }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void loadPresets() {
        presetList.clear();
        SharedPreferences sp = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        int presetsVer = sp.getInt(PREF_PRESETS_VERSION, 0);

        String raw = sp.getString(KEY_PRESETS, null);
        if (raw != null && !raw.trim().isEmpty()) {
            String[] items = raw.split("\n");
            for (String item : items) {
                PresetItem p = PresetItem.fromJson(item);
                if (p != null && !presetList.contains(p)) {
                    presetList.add(p);
                }
            }
        }

        if (presetsVer < PresetItem.DEFAULTS_VERSION || presetList.isEmpty()) {
            // Refresh the built-in rete presets while keeping every preset the user added.
            java.util.List<PresetItem> merged = PresetItem.mergeDefaults(presetList);
            presetList.clear();
            presetList.addAll(merged);
            sp.edit().putInt(PREF_PRESETS_VERSION, PresetItem.DEFAULTS_VERSION).commit();
            savePresets();
        }
    }

    private void saveNewPreset(String name, String url) {
        PresetItem candidate = new PresetItem(name, url);
        if (presetList.contains(candidate)) {
            Toast.makeText(MainActivity.this, R.string.toast_preset_exists, Toast.LENGTH_SHORT).show();
            return;
        }

        // If currently downloaded file belongs to this URL, capture its metadata
        if (lastDownloadedFile != null && lastDownloadedFile.exists()) {
            String finalUrl = getFinalDownloadUrl();
            if (url.equals(finalUrl) || (currentTemplate != null && url.equals(currentTemplate.getTemplate()))) {
                candidate.lastFileName = lastDownloadedFile.getName();
                candidate.lastFileSize = lastDownloadedFile.length();
                candidate.lastDownloadedAt = System.currentTimeMillis();
                candidate.lastSha256 = lastComputedSha256;
                if (lastSignatureResult != null && lastSignatureResult.currentCert != null) {
                    candidate.lastSigFingerprint = lastSignatureResult.currentCert.sha256Fingerprint;
                    candidate.lastAuthor = lastSignatureResult.currentCert.getDisplayAuthor();
                }
                candidate.lastVersion = extractVersionInfo(lastDownloadedFile);
            }
        }

        presetList.add(candidate);
        savePresets();
        renderPresets();
        Toast.makeText(MainActivity.this, R.string.toast_preset_saved, Toast.LENGTH_SHORT).show();
    }

    private void savePresets() {
        SharedPreferences sp = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        StringBuilder sb = new StringBuilder();
        for (PresetItem p : presetList) {
            sb.append(p.toJson()).append("\n");
        }
        sp.edit().putString(KEY_PRESETS, sb.toString()).commit();
    }

    private void setupUrlButtons() {
        findViewById(R.id.btn_paste_url).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String text = readClipboard();
                if (text == null || text.trim().length() == 0) {
                    Toast.makeText(MainActivity.this, R.string.toast_clipboard_empty, Toast.LENGTH_SHORT).show();
                    return;
                }
                editUrl.setText(text.trim());
                editUrl.setSelection(editUrl.getText().length());
            }
        });
        findViewById(R.id.btn_clear_url).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                editUrl.setText("");
                editUrl.requestFocus();
            }
        });
    }

    // ------------------------------------------------------------------ settings export / import

    private void setupSettingsTransfer() {
        findViewById(R.id.btn_settings_export).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                exportSettings();
            }
        });
        findViewById(R.id.btn_settings_import).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                chooseSettingsSource();
            }
        });
    }

    private SettingsBundle currentSettings() {
        SettingsBundle b = new SettingsBundle();
        try {
            b.appVersion = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception ignored) {
            b.appVersion = "";
        }
        b.builtInTls = chkPureTls.isChecked();
        b.autoUpgrade = chkAutoUpgrade.isChecked();
        b.presets.addAll(presetList);
        SharedPreferences sp = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        for (Map.Entry<String, ?> e : sp.getAll().entrySet()) {
            if (e.getKey().startsWith("sig_fp_") && e.getValue() instanceof String) {
                String pkg = e.getKey().substring("sig_fp_".length());
                b.signers.put(pkg, new String[] { (String) e.getValue(), sp.getString("sig_auth_" + pkg, "") });
            }
        }
        return b;
    }

    private void exportSettings() {
        final String text = currentSettings().write();
        String stamp = new java.text.SimpleDateFormat("yyyyMMdd-HHmm", java.util.Locale.US)
                .format(new java.util.Date());
        File file = new File(chooseDownloadDir(), SettingsBundle.FILE_PREFIX + "-" + stamp + SettingsBundle.FILE_SUFFIX);
        String message;
        try {
            java.io.OutputStream out = new java.io.FileOutputStream(file);
            try {
                out.write(text.getBytes("UTF-8"));
            } finally {
                out.close();
            }
            if (isPrivateDownload(file)) file.setReadable(true, false);
            message = getString(R.string.settings_exported, file.getAbsolutePath());
        } catch (Exception e) {
            message = getString(R.string.settings_export_failed, String.valueOf(e.getMessage()));
        }
        new AlertDialog.Builder(this)
                .setMessage(message)
                .setPositiveButton(android.R.string.ok, null)
                .setNeutralButton(R.string.settings_copy_text, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        copyToClipboard(text);
                        Toast.makeText(MainActivity.this, R.string.settings_copied, Toast.LENGTH_SHORT).show();
                    }
                })
                .show();
    }

    /** Settings files in the Download folder (and the app-storage fallback), newest first. */
    private List<File> settingsFiles() {
        List<File> found = new ArrayList<File>();
        File[] dirs = { Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                new File(getFilesDir(), "downloads") };
        for (File dir : dirs) {
            File[] files = dir == null ? null : dir.listFiles();
            if (files == null) continue;
            for (File f : files) {
                String n = f.getName().toLowerCase(java.util.Locale.US);
                if (f.isFile() && n.startsWith(SettingsBundle.FILE_PREFIX)
                        && (n.endsWith(".ini") || n.endsWith(".txt") || n.endsWith(".toml"))) {
                    found.add(f);
                }
            }
        }
        java.util.Collections.sort(found, new java.util.Comparator<File>() {
            @Override
            public int compare(File a, File b) {
                return a.lastModified() < b.lastModified() ? 1 : a.lastModified() > b.lastModified() ? -1 : 0;
            }
        });
        return found.size() > 20 ? found.subList(0, 20) : found;
    }

    private void chooseSettingsSource() {
        final List<File> files = settingsFiles();
        final String[] items = new String[files.size() + 1];
        for (int i = 0; i < files.size(); i++) items[i] = files.get(i).getName();
        items[files.size()] = getString(R.string.settings_from_clipboard);
        AlertDialog.Builder dialog = new AlertDialog.Builder(this).setTitle(R.string.settings_import_title);
        if (files.isEmpty()) {
            dialog.setMessage(getString(R.string.settings_no_files))
                    .setPositiveButton(R.string.settings_from_clipboard, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface d, int which) {
                            previewImport(readClipboard());
                        }
                    })
                    .setNegativeButton(android.R.string.cancel, null);
        } else {
            dialog.setItems(items, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface d, int which) {
                    previewImport(which < files.size() ? readSmallFile(files.get(which)) : readClipboard());
                }
            }).setNegativeButton(android.R.string.cancel, null);
        }
        dialog.show();
    }

    private static String readSmallFile(File f) {
        try {
            if (f.length() > 1024 * 1024) return null;
            java.io.InputStream in = new java.io.FileInputStream(f);
            try {
                java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) bytes.write(buf, 0, n);
                return new String(bytes.toByteArray(), "UTF-8");
            } finally {
                in.close();
            }
        } catch (Exception e) {
            return null;
        }
    }

    /** Shows what the file holds and what will change, then applies it on confirmation. */
    private void previewImport(String text) {
        final SettingsBundle b;
        try {
            b = SettingsBundle.parse(text);
        } catch (IllegalArgumentException e) {
            Toast.makeText(this, getString(R.string.settings_import_failed, e.getMessage()), Toast.LENGTH_LONG).show();
            return;
        }
        final SettingsBundle.Merge merge = SettingsBundle.mergePresets(presetList, b.presets);
        StringBuilder msg = new StringBuilder(getString(R.string.settings_import_confirm,
                b.presets.size(), merge.added, merge.updated, b.signers.size()));
        if (!b.complaints.isEmpty()) {
            msg.append("\n\n");
            for (int i = 0; i < b.complaints.size() && i < 8; i++) msg.append("• ").append(b.complaints.get(i)).append('\n');
        }
        new AlertDialog.Builder(this)
                .setTitle(R.string.settings_import_title)
                .setMessage(msg.toString())
                .setPositiveButton(R.string.btn_import, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        applyImport(b, merge);
                    }
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void applyImport(SettingsBundle b, SettingsBundle.Merge merge) {
        presetList.clear();
        presetList.addAll(merge.presets);
        savePresets();
        renderPresets();
        if (b.builtInTls != null) {
            chkPureTls.setChecked(b.builtInTls);   // its listener stores the choice
        }
        if (b.autoUpgrade != null) {
            chkAutoUpgrade.setChecked(b.autoUpgrade);
        }
        // Signing keys already recorded on this phone win: an imported file must not be able to
        // replace a key this phone has seen with another one.
        SharedPreferences sp = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        SharedPreferences.Editor ed = sp.edit();
        for (Map.Entry<String, String[]> e : b.signers.entrySet()) {
            if (!sp.contains("sig_fp_" + e.getKey())) {
                ed.putString("sig_fp_" + e.getKey(), e.getValue()[0]);
                ed.putString("sig_auth_" + e.getKey(), e.getValue()[1]);
            }
        }
        ed.commit();
        Toast.makeText(this, R.string.settings_imported, Toast.LENGTH_SHORT).show();
    }

    @SuppressWarnings("deprecation")
    private String readClipboard() {
        try {
            if (Build.VERSION.SDK_INT >= 11) {
                android.content.ClipboardManager cm =
                        (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm == null || !cm.hasPrimaryClip() || cm.getPrimaryClip().getItemCount() == 0) return null;
                CharSequence t = cm.getPrimaryClip().getItemAt(0).coerceToText(this);
                return t == null ? null : t.toString();
            }
            android.text.ClipboardManager cm =
                    (android.text.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            CharSequence t = cm == null ? null : cm.getText();
            return t == null ? null : t.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private void setupUrlWatcher() {
        editUrl.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {}

            @Override
            public void afterTextChanged(Editable s) {
                handleUrlChanged(s.toString());
            }
        });

        // Trigger initial template parse
        handleUrlChanged(editUrl.getText().toString());
    }

    private void handleUrlChanged(String text) {
        currentTemplate = new UrlTemplate(text);
        List<String> placeholders = currentTemplate.getPlaceholders();

        if (placeholders.isEmpty()) {
            layoutVariables.setVisibility(View.GONE);
            variablesFields.removeAllViews();
            variableInputs.clear();
            txtResolvedPreview.setText("");
            return;
        }

        // Cache previous values
        Map<String, String> oldValues = new HashMap<String, String>();
        for (Map.Entry<String, EditText> entry : variableInputs.entrySet()) {
            oldValues.put(entry.getKey(), entry.getValue().getText().toString());
        }

        variablesFields.removeAllViews();
        variableInputs.clear();

        for (final String placeholder : placeholders) {
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setPadding(0, 2, 0, 2);

            TextView label = new TextView(this);
            label.setText("{" + placeholder + "}: ");
            label.setTextSize(13);
            label.setTextColor(Color.parseColor("#333333"));
            label.setMinWidth(70);

            EditText input = new EditText(this);
            input.setLayoutParams(new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.FILL_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT));
            input.setTextSize(13);
            input.setHint("Value for {" + placeholder + "}");
            input.setSingleLine(true);

            if (oldValues.containsKey(placeholder)) {
                input.setText(oldValues.get(placeholder));
            }

            input.addTextChangedListener(new TextWatcher() {
                @Override
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

                @Override
                public void onTextChanged(CharSequence s, int start, int before, int count) {}

                @Override
                public void afterTextChanged(Editable s) {
                    updateResolvedPreview();
                }
            });

            row.addView(label);
            row.addView(input);
            variablesFields.addView(row);
            variableInputs.put(placeholder, input);
        }

        layoutVariables.setVisibility(View.VISIBLE);
        updateResolvedPreview();
    }

    private void updateResolvedPreview() {
        if (currentTemplate == null) return;
        Map<String, String> values = new HashMap<String, String>();
        for (Map.Entry<String, EditText> entry : variableInputs.entrySet()) {
            values.put(entry.getKey(), entry.getValue().getText().toString());
        }
        String resolved = currentTemplate.resolve(values);
        txtResolvedPreview.setText("Resolved URL:\n" + resolved);
    }

    private String getFinalDownloadUrl() {
        if (currentTemplate == null || !currentTemplate.hasPlaceholders()) {
            return editUrl.getText().toString().trim();
        }
        Map<String, String> values = new HashMap<String, String>();
        for (Map.Entry<String, EditText> entry : variableInputs.entrySet()) {
            values.put(entry.getKey(), entry.getValue().getText().toString().trim());
        }
        return currentTemplate.resolve(values);
    }

    private void setupChecksumControls() {
        editExpectedChecksum.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {}

            @Override
            public void afterTextChanged(Editable s) {
                // Paste and Clear stay visible, like the ones beside the URL.
            }
        });

        findViewById(R.id.btn_paste_checksum).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String text = readClipboard();
                if (text == null || text.trim().length() == 0) {
                    Toast.makeText(MainActivity.this, R.string.toast_clipboard_empty, Toast.LENGTH_SHORT).show();
                    return;
                }
                editExpectedChecksum.setText(text.trim());
                editExpectedChecksum.setSelection(editExpectedChecksum.getText().length());
            }
        });

        btnClearChecksum.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                editExpectedChecksum.setText("");
            }
        });

        btnCopyHash.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (lastComputedSha256 != null && !lastComputedSha256.isEmpty()) {
                    copyToClipboard(lastComputedSha256);
                    Toast.makeText(MainActivity.this, R.string.toast_copied, Toast.LENGTH_SHORT).show();
                }
            }
        });

        btnVerifyHash.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (lastDownloadedFile == null || !lastDownloadedFile.exists()) {
                    Toast.makeText(MainActivity.this, "No file downloaded yet", Toast.LENGTH_SHORT).show();
                    return;
                }
                showVerifyDialog();
            }
        });
    }

    private void showVerifyDialog() {
        final EditText input = new EditText(this);
        input.setHint(R.string.checksum_hint);
        input.setSingleLine(true);
        input.setTextSize(12);

        new AlertDialog.Builder(this)
                .setTitle(R.string.btn_verify_hash)
                .setMessage(R.string.lbl_checksum)
                .setView(input)
                .setPositiveButton("Verify", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        String hash = input.getText().toString().trim();
                        if (!hash.isEmpty()) {
                            editExpectedChecksum.setText(hash);
                            verifyDownloadedFile(lastDownloadedFile, hash);
                        }
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void verifyDownloadedFile(File file, String expectedInput) {
        if (file == null || !file.exists()) return;

        if (expectedInput != null && !expectedInput.trim().isEmpty()) {
            ChecksumVerifier.Result res = ChecksumVerifier.verify(file, expectedInput);
            if (res.matched) {
                hasChecksumMismatch = false;
                txtChecksumResult.setTextColor(Color.parseColor("#1b5e20")); // Dark Green
                txtChecksumResult.setText(getString(R.string.checksum_verified, res.algorithm) + "\n" + res.actualHash);
            } else if (res.error != null) {
                hasChecksumMismatch = false;
                txtChecksumResult.setTextColor(Color.parseColor("#b71c1c")); // Dark Red
                txtChecksumResult.setText("Checksum error: " + res.error + "\nComputed SHA-256: " + lastComputedSha256);
            } else {
                hasChecksumMismatch = true;
                txtChecksumResult.setTextColor(Color.parseColor("#b71c1c")); // Dark Red
                txtChecksumResult.setText(getString(R.string.checksum_mismatch, res.expectedHash, res.algorithm, res.actualHash));
            }
        } else {
            hasChecksumMismatch = false;
            txtChecksumResult.setTextColor(Color.parseColor("#333333"));
            txtChecksumResult.setText(getString(R.string.checksum_computed, "SHA-256", lastComputedSha256));
        }

        layoutChecksumResult.setVisibility(View.VISIBLE);
    }

    private void copyToClipboard(String text) {
        if (Build.VERSION.SDK_INT >= 11) {
            android.content.ClipboardManager cm = (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(android.content.ClipData.newPlainText("hash", text));
            }
        } else {
            android.text.ClipboardManager cm = (android.text.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setText(text);
            }
        }
    }

    private void setupDownloadControls() {
        btnDownload.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startDownload();
            }
        });

        btnCancel.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                for (DownloadTask t : sQueue.snapshot()) {
                    if (t.state == DownloadTask.State.RUNNING) {
                        sQueue.cancel(t.id);
                    }
                }
            }
        });
    }

    private void startDownload() {
        String url = getFinalDownloadUrl();
        if (url.isEmpty()) {
            Toast.makeText(this, "Please enter a valid URL", Toast.LENGTH_SHORT).show();
            return;
        }

        String lower = url.toLowerCase();
        if (!lower.startsWith("http://") && !lower.startsWith("https://") && !lower.startsWith("ftp://")) {
            Toast.makeText(this, "URL must start with http://, https://, or ftp://", Toast.LENGTH_LONG).show();
            return;
        }

        final File destDir = chooseDownloadDir();

        String template = currentTemplate != null && !currentTemplate.getPlaceholders().isEmpty()
                ? currentTemplate.getTemplate() : editUrl.getText().toString().trim();
        String version = null;
        EditText v1 = variableInputs.get("1");
        if (v1 == null) v1 = variableInputs.get("version");
        if (v1 != null && v1.getText().toString().trim().length() > 0) {
            version = v1.getText().toString().trim();
        }
        sQueue.enqueue(url, destDir, chkInsecureSsl.isChecked(), chkPureTls.isChecked(),
                editExpectedChecksum.getText().toString().trim(), template, version);
        Toast.makeText(this, R.string.queue_added, Toast.LENGTH_SHORT).show();
        scrollView.smoothScrollTo(0, 0);
    }

    /** Largest index page read; a release list or directory listing is far smaller. */
    private static final long MAX_INDEX_BYTES = 1024 * 1024;

    /**
     * Latest: reads the preset's index page, takes the address that fits the preset URL and sorts
     * last (Windows order), shows it in the URL bar and queues it. The download is recorded under
     * the preset as with Use + Download.
     */
    private void downloadLatest(final PresetItem item) {
        final String index = item.index.trim();
        final File dir = new File(getCacheDir(), "index-" + System.currentTimeMillis());
        dir.mkdirs();
        Toast.makeText(this, getString(R.string.latest_looking, item.getDisplayName()), Toast.LENGTH_SHORT).show();
        final DownloadEngine engine = new DownloadEngine();
        engine.download(index, dir, chkInsecureSsl.isChecked(), chkPureTls.isChecked(), new DownloadEngine.Listener() {
            @Override
            public void onStart(String filename, long totalBytes) {
                if (totalBytes > MAX_INDEX_BYTES) engine.cancel();
            }

            @Override
            public void onProgress(long bytesRead, long totalBytes, int percent, long bytesPerSec) {
                if (bytesRead > MAX_INDEX_BYTES) engine.cancel();
            }

            @Override
            public void onComplete(File file) {
                final String page = readSmallFile(file);
                deleteTree(dir);
                final IndexMatcher.Match m = page == null ? null : IndexMatcher.latest(page, index, item.url);
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (page == null) {
                            finishLatest(item, index, null, "too large");
                        } else {
                            finishLatest(item, index, m, null);
                        }
                    }
                });
            }

            @Override
            public void onError(final Exception ex) {
                deleteTree(dir);
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        finishLatest(item, index, null, ex.getMessage() != null ? ex.getMessage() : ex.toString());
                    }
                });
            }

            @Override
            public void onCancel() {
                deleteTree(dir);
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        finishLatest(item, index, null, "larger than 1 MB");
                    }
                });
            }
        });
    }

    private void finishLatest(PresetItem item, String index, IndexMatcher.Match m, String error) {
        if (isFinishing()) return;
        if (error != null) {
            Toast.makeText(this, getString(R.string.latest_failed, index, error), Toast.LENGTH_LONG).show();
            return;
        }
        if (m == null) {
            Toast.makeText(this, getString(R.string.latest_none, index), Toast.LENGTH_LONG).show();
            return;
        }
        // Same view as Use, with the version found: the URL bar then shows what is downloaded.
        selectAndLoadPreset(item, false);
        if (!new UrlTemplate(item.url).hasPlaceholders()) {
            editUrl.setText(m.url);   // a pattern with only * is not a template
        } else if (m.version != null) {
            for (EditText input : variableInputs.values()) {
                input.setText(m.version);
            }
        }
        sQueue.enqueue(m.url, chooseDownloadDir(), chkInsecureSsl.isChecked(), chkPureTls.isChecked(),
                editExpectedChecksum.getText().toString().trim(), item.url, m.version);
        Toast.makeText(this, getString(R.string.latest_found, m.url.substring(m.url.lastIndexOf('/') + 1)),
                Toast.LENGTH_LONG).show();
    }

    private static void deleteTree(File f) {
        File[] children = f.listFiles();
        if (children != null) {
            for (File c : children) deleteTree(c);
        }
        f.delete();
    }

    // ------------------------------------------------------------------ download queue

    private void setupQueue() {
        synchronized (MainActivity.class) {
            if (sQueue == null) {
                final SharedPreferences sp = getApplicationContext()
                        .getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
                sQueue = new DownloadQueue(new DownloadQueue.Store() {
                    @Override
                    public String load() {
                        return sp.getString(KEY_QUEUE, null);
                    }

                    @Override
                    public void save(String data) {
                        sp.edit().putString(KEY_QUEUE, data).commit();
                    }
                }, DownloadQueue.defaultEngines());
            }
        }
        sQueue.setListener(new DownloadQueue.Listener() {
            @Override
            public void onTaskChanged(final DownloadTask task) {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (task == null || !updateQueueRow(task)) {
                            renderQueue();
                        }
                    }
                });
            }

            @Override
            public void onTaskCompleted(DownloadTask task) {
                verifyCompleted(task);
            }
        });
        // Downloads that finished while no screen was listening (e.g. during a rotation) still
        // get their checksum/signature checks and install prompt.
        for (DownloadTask t : sQueue.snapshot()) {
            if (t.state == DownloadTask.State.DONE && !t.verified) {
                verifyCompleted(t);
            }
        }
        btnQueueClear.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                sQueue.clearFinished();
            }
        });
        btnQueueSelectAll.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                List<DownloadTask> all = sQueue.snapshot();
                if (selectedQueueIds.size() == all.size()) {
                    selectedQueueIds.clear();
                } else {
                    for (DownloadTask t : all) selectedQueueIds.add(t.id);
                }
                renderQueue();
            }
        });
        btnQueueDeleteSelected.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                for (Long id : new ArrayList<Long>(selectedQueueIds)) {
                    sQueue.remove(id);
                }
                selectedQueueIds.clear();
                renderQueue();
            }
        });
        renderQueue();
    }

    @Override
    protected void onDestroy() {
        if (sQueue != null) {
            sQueue.setListener(null);
        }
        super.onDestroy();
    }

    private static final java.util.Set<Long> sVerifying = new java.util.HashSet<Long>();

    /** Hashes off the UI thread, then runs the checks and install prompt on it. Once per entry. */
    private void verifyCompleted(final DownloadTask task) {
        synchronized (sVerifying) {
            if (!sVerifying.add(task.id)) return;
        }
        new Thread(new Runnable() {
            @Override
            public void run() {
                final File file = new File(task.filePath);
                String sha = null;
                if (file.exists()) {
                    try {
                        sha = ChecksumVerifier.computeHash(file, "SHA-256");
                    } catch (Exception e) {
                        sha = null;
                    }
                }
                final String hash = sha;
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            if (!file.exists()) {
                                // Only a verdict when the storage is actually there; right after
                                // boot, or while mounted on a PC, shared storage may be missing.
                                if (isPrivateDownload(file) || Environment.MEDIA_MOUNTED.equals(
                                        Environment.getExternalStorageState())) {
                                    sQueue.markVerified(task.id, null, DownloadTask.WARN_MISSING);
                                }
                            } else {
                                handleCompletedDownload(task, file, hash);
                            }
                        } finally {
                            synchronized (sVerifying) {
                                sVerifying.remove(task.id);
                            }
                        }
                    }
                });
            }
        }, "VerifyThread").start();
    }

    private void handleCompletedDownload(DownloadTask task, File destinationFile, String sha256) {
        lastComputedSha256 = sha256;
        lastDownloadedFile = destinationFile;
        btnInstall.setVisibility(View.GONE);
        layoutChecksumResult.setVisibility(View.GONE);
        hasChecksumMismatch = false;
        layoutSignatureResult.setVisibility(View.GONE);
        hasSignatureMismatch = false;
        lastSignatureResult = null;
        if (isPrivateDownload(destinationFile)) {
            // Readable by the package installer; see chooseDownloadDir().
            destinationFile.setReadable(true, false);
        }
        txtStatus.setText((isPrivateDownload(destinationFile)
                ? "Shared storage unavailable. Saved in app storage: " : "Saved to: ")
                + destinationFile.getAbsolutePath()
                + " (" + formatBytes(destinationFile.length()) + ")"
                + (task.tlsSummary != null ? "\n" + task.tlsSummary : ""));

        verifyDownloadedFile(destinationFile, task.expectedChecksum);

        if (destinationFile.getName().toLowerCase().endsWith(".apk")) {
            btnInstall.setVisibility(View.VISIBLE);
            verifyApkSignature(destinationFile);
            sQueue.markVerified(task.id, sha256, warningsFor(hasChecksumMismatch, hasSignatureMismatch));
            updatePresetDownloadRecord(destinationFile, task.template, task.url, task.version);
            if (hasChecksumMismatch) {
                // Keep visible for manual install button review
            } else if (hasSignatureMismatch) {
                promptSignatureMismatchDialog(destinationFile);
            } else if (!startUpgrade(destinationFile)) {
                promptAutoInstall(destinationFile);
            }
        } else {
            sQueue.markVerified(task.id, sha256, warningsFor(hasChecksumMismatch, false));
            updatePresetDownloadRecord(destinationFile, task.template, task.url, task.version);
            Toast.makeText(MainActivity.this, "File saved successfully", Toast.LENGTH_SHORT).show();
        }
    }

    private static String warningsFor(boolean checksum, boolean signature) {
        if (checksum && signature) return DownloadTask.WARN_CHECKSUM + "," + DownloadTask.WARN_SIGNATURE;
        if (checksum) return DownloadTask.WARN_CHECKSUM;
        if (signature) return DownloadTask.WARN_SIGNATURE;
        return null;
    }

    /** Rows shown: running and waiting entries in queue order, then finished ones, newest first. */
    private void renderQueue() {
        List<DownloadTask> all = sQueue.snapshot();
        List<DownloadTask> ordered = new ArrayList<DownloadTask>();
        for (DownloadTask t : all) {
            if (t.isActive()) ordered.add(t);
        }
        for (int i = all.size() - 1; i >= 0; i--) {
            if (!all.get(i).isActive()) ordered.add(all.get(i));
        }
        layoutQueueList.removeAllViews();
        queueRows.clear();
        boolean anyFinished = false;
        for (DownloadTask t : ordered) {
            anyFinished |= !t.isActive();
            layoutQueueList.addView(buildQueueRow(t));
        }
        queueCount = ordered.size();
        java.util.Set<Long> present = new java.util.HashSet<Long>();
        for (DownloadTask t : ordered) present.add(t.id);
        selectedQueueIds.retainAll(present);
        layoutQueueSection.setVisibility(ordered.isEmpty() ? View.GONE : View.VISIBLE);
        btnQueueClear.setVisibility(anyFinished ? View.VISIBLE : View.GONE);
        updateQueueSelectionButton();
        btnCancel.setEnabled(sQueue.isBusy());
    }

    private static final class QueueRow {
        DownloadTask.State state;
        String warning;
        TextView body;
        ProgressBar progress;
    }

    private final Map<Long, QueueRow> queueRows = new HashMap<Long, QueueRow>();

    private void updateQueueSelectionButton() {
        int n = selectedQueueIds.size();
        btnQueueDeleteSelected.setText(getString(R.string.btn_delete_selected, n));
        btnQueueDeleteSelected.setEnabled(n > 0);
        btnQueueSelectAll.setText(n > 0 && n == queueCount ? R.string.btn_select_none : R.string.btn_select_all);
    }

    /** Updates progress in place; returns false when the row must be rebuilt. */
    private boolean updateQueueRow(DownloadTask t) {
        QueueRow row = queueRows.get(t.id);
        if (row == null || row.state != t.state) return false;
        if (row.warning == null ? t.warning != null : !row.warning.equals(t.warning)) return false;
        row.body.setText(queueBody(t));
        applyProgress(row.progress, t);
        return true;
    }

    /** File name / state / URL as one paragraph, like a preset. */
    private CharSequence queueBody(DownloadTask t) {
        android.text.SpannableStringBuilder sb = new android.text.SpannableStringBuilder();
        String name = t.displayName();
        sb.append(name);
        sb.setSpan(new android.text.style.StyleSpan(android.graphics.Typeface.BOLD), 0, name.length(), 0);
        sb.setSpan(new android.text.style.ForegroundColorSpan(0xFF263238), 0, name.length(), 0);
        sb.append("  /  ");
        int st = sb.length();
        sb.append(queueStatusText(t));
        int colour = t.state == DownloadTask.State.FAILED ? 0xFFCC0000
                : t.state == DownloadTask.State.DONE && t.warning != null ? 0xFFE65100
                : t.state == DownloadTask.State.DONE ? 0xFF2E7D32 : 0xFF555555;
        sb.setSpan(new android.text.style.ForegroundColorSpan(colour), st, sb.length(), 0);
        sb.append("  /  ");
        int us = sb.length();
        sb.append(t.url);
        sb.setSpan(new android.text.style.ForegroundColorSpan(0xFF0277BD), us, sb.length(), 0);
        sb.setSpan(new android.text.style.RelativeSizeSpan(0.9f), us, sb.length(), 0);
        return sb;
    }

    private View buildQueueRow(final DownloadTask t) {
        View row = LayoutInflater.from(this).inflate(R.layout.item_queue, layoutQueueList, false);
        CheckBox chk = (CheckBox) row.findViewById(R.id.chk_queue_select);
        chk.setChecked(selectedQueueIds.contains(t.id));
        chk.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) selectedQueueIds.add(t.id); else selectedQueueIds.remove(t.id);
                updateQueueSelectionButton();
            }
        });

        LinearLayout buttons = (LinearLayout) row.findViewById(R.id.layout_queue_actions);
        switch (t.state) {
            case QUEUED:
            case RUNNING:
                addQueueButton(buttons, R.string.queue_cancel, false, new Runnable() {
                    public void run() { sQueue.cancel(t.id); }
                });
                break;
            case FAILED:
            case CANCELLED:
                addQueueButton(buttons, R.string.queue_retry, false, new Runnable() {
                    public void run() { sQueue.retry(t.id); }
                });
                addQueueButton(buttons, R.string.queue_remove, true, new Runnable() {
                    public void run() { sQueue.remove(t.id); }
                });
                break;
            case DONE:
                if (t.fileName != null && t.fileName.toLowerCase().endsWith(".apk")) {
                    addQueueButton(buttons, R.string.queue_install, false, new Runnable() {
                        public void run() { installFromQueue(t); }
                    });
                }
                addQueueButton(buttons, R.string.queue_remove, true, new Runnable() {
                    public void run() { sQueue.remove(t.id); }
                });
                break;
        }

        TextView body = (TextView) row.findViewById(R.id.txt_queue_body);
        body.setText(queueBody(t));
        ProgressBar progress = (ProgressBar) row.findViewById(R.id.progress_queue);
        applyProgress(progress, t);

        QueueRow qr = new QueueRow();
        qr.state = t.state;
        qr.warning = t.warning;
        qr.body = body;
        qr.progress = progress;
        queueRows.put(t.id, qr);
        return row;
    }

    private void installFromQueue(DownloadTask t) {
        File f = new File(t.filePath);
        if (!f.exists()) {
            Toast.makeText(MainActivity.this, R.string.queue_file_missing, Toast.LENGTH_SHORT).show();
            return;
        }
        // Same warnings as right after the download. The signature is read again so the
        // dialog can name both certificates after a restart.
        if (t.hasWarning(DownloadTask.WARN_SIGNATURE)) {
            verifyApkSignature(f);
        }
        hasSignatureMismatch = t.hasWarning(DownloadTask.WARN_SIGNATURE);
        if (t.hasWarning(DownloadTask.WARN_CHECKSUM)) {
            promptChecksumMismatchDialog(f);
        } else if (hasSignatureMismatch) {
            promptSignatureMismatchDialog(f);
        } else {
            launchApkInstaller(f);
        }
    }

    /** A bordered word-button, the same as the preset actions. */
    private void addQueueButton(LinearLayout parent, int text, boolean danger, final Runnable action) {
        Button b = new Button(this);
        b.setText(text);
        b.setTypeface(null, android.graphics.Typeface.BOLD);
        if (danger) b.setTextColor(getResources().getColorStateList(R.color.btn_danger_text));
        float d = getResources().getDisplayMetrics().density;
        b.setMinWidth((int) (40 * d));
        b.setPadding((int) (8 * d), (int) (3 * d), (int) (8 * d), (int) (3 * d));
        b.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                action.run();
            }
        });
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.leftMargin = (int) (4 * d);
        parent.addView(b, lp);
    }

    /** Every entry ends with its progress bar: full when done, where it stopped when not. */
    private static void applyProgress(ProgressBar bar, DownloadTask t) {
        int pct = t.percent();
        bar.setVisibility(View.VISIBLE);
        bar.setIndeterminate(t.state == DownloadTask.State.RUNNING && pct < 0);
        bar.setProgress(pct >= 0 ? pct : 0);
    }

    private String queueStatusText(DownloadTask t) {
        StringBuilder sb = new StringBuilder();
        switch (t.state) {
            case QUEUED:
                sb.append(getString(R.string.queue_waiting));
                break;
            case RUNNING:
                if (t.fileName == null) {
                    // Not connected yet: DNS, TCP and the TLS handshake (a retry with the
                    // built-in engine can take a few seconds on an old phone).
                    sb.append(getString(R.string.queue_connecting));
                    break;
                }
                sb.append(getString(R.string.queue_downloading)).append(" · ").append(formatBytes(t.bytesDone));
                if (t.bytesTotal > 0) {
                    sb.append(" / ").append(formatBytes(t.bytesTotal)).append(" (").append(t.percent()).append("%)");
                }
                if (t.bytesPerSec > 0) sb.append(" · ").append(formatBytes(t.bytesPerSec)).append("/s");
                break;
            case DONE:
                sb.append(getString(R.string.queue_done)).append(" · ").append(formatBytes(t.bytesDone));
                if (t.hasWarning(DownloadTask.WARN_CHECKSUM)) sb.append(" · ").append(getString(R.string.queue_warn_checksum));
                if (t.hasWarning(DownloadTask.WARN_SIGNATURE)) sb.append(" · ").append(getString(R.string.queue_warn_signature));
                if (t.hasWarning(DownloadTask.WARN_MISSING)) sb.append(" · ").append(getString(R.string.queue_file_missing));
                break;
            case FAILED:
                sb.append(getString(R.string.queue_failed)).append(": ").append(
                        DownloadQueue.INTERRUPTED.equals(t.error) ? getString(R.string.queue_interrupted) : t.error);
                break;
            case CANCELLED:
                sb.append(getString(R.string.queue_cancelled));
                break;
        }
        return sb.toString();
    }

    private void setupInstallControl() {
        btnInstall.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (lastDownloadedFile != null && lastDownloadedFile.exists()) {
                    if (hasChecksumMismatch) {
                        promptChecksumMismatchDialog(lastDownloadedFile);
                    } else if (hasSignatureMismatch) {
                        promptSignatureMismatchDialog(lastDownloadedFile);
                    } else {
                        launchApkInstaller(lastDownloadedFile);
                    }
                } else {
                    Toast.makeText(MainActivity.this, "APK file not found", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    private void promptChecksumMismatchDialog(final File apkFile) {
        new AlertDialog.Builder(MainActivity.this)
                .setTitle(R.string.dialog_mismatch_title)
                .setMessage(R.string.dialog_mismatch_msg)
                .setPositiveButton(R.string.dialog_btn_install_anyway, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        if (hasSignatureMismatch) {
                            promptSignatureMismatchDialog(apkFile);
                        } else {
                            launchApkInstaller(apkFile);
                        }
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void promptSignatureMismatchDialog(final File apkFile) {
        String existingSrc = (lastSignatureResult != null && lastSignatureResult.existingSource != null)
                ? lastSignatureResult.existingSource : "Existing";
        String existingFp = (lastSignatureResult != null && lastSignatureResult.existingFingerprint != null)
                ? lastSignatureResult.existingFingerprint : "Unknown";
        String currentFp = (lastSignatureResult != null && lastSignatureResult.currentCert != null)
                ? lastSignatureResult.currentCert.sha256Fingerprint : "Unknown";

        String msg = getString(R.string.dialog_sig_mismatch_msg, existingSrc, existingFp, currentFp);

        new AlertDialog.Builder(this)
                .setTitle(R.string.dialog_sig_mismatch_title)
                .setMessage(msg)
                .setPositiveButton(R.string.dialog_btn_sig_install_anyway, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        if (lastSignatureResult != null && lastSignatureResult.currentCert != null) {
                            String pkg = getPackageNameFromArchive(apkFile);
                            saveSignatureRecord(pkg, lastSignatureResult.currentCert);
                        }
                        launchApkInstaller(apkFile);
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private String getPackageNameFromArchive(File apkFile) {
        try {
            PackageManager pm = getPackageManager();
            PackageInfo pi = pm.getPackageArchiveInfo(apkFile.getAbsolutePath(), 0);
            if (pi != null && pi.packageName != null) {
                return pi.packageName;
            }
        } catch (Exception ignored) {}
        return null;
    }

    private void verifyApkSignature(File apkFile) {
        ApkSignatureVerifier.CertInfo currentCert = null;
        String packageName = null;

        // Try PackageManager.getPackageArchiveInfo first
        try {
            PackageManager pm = getPackageManager();
            PackageInfo pi = pm.getPackageArchiveInfo(apkFile.getAbsolutePath(), PackageManager.GET_SIGNATURES);
            if (pi != null) {
                packageName = pi.packageName;
                if (pi.signatures != null && pi.signatures.length > 0) {
                    currentCert = ApkSignatureVerifier.fromDerBytes(pi.signatures[0].toByteArray());
                }
            }
        } catch (Exception ignored) {}

        // Fallback to pure Java APK reading if signatures not populated
        if (currentCert == null) {
            currentCert = ApkSignatureVerifier.fromApkFile(apkFile);
        }

        if (currentCert == null) {
            layoutSignatureResult.setVisibility(View.GONE);
            hasSignatureMismatch = false;
            lastSignatureResult = null;
            return;
        }

        // Check if installed on device
        ApkSignatureVerifier.CertInfo installedCert = null;
        if (packageName != null) {
            try {
                PackageInfo installedPi = getPackageManager().getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
                if (installedPi != null && installedPi.signatures != null && installedPi.signatures.length > 0) {
                    installedCert = ApkSignatureVerifier.fromDerBytes(installedPi.signatures[0].toByteArray());
                }
            } catch (PackageManager.NameNotFoundException ignored) {
            } catch (Exception ignored) {}
        }

        // Check saved history in SharedPreferences
        SharedPreferences sp = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String savedFingerprint = null;
        String savedAuthor = null;
        if (packageName != null) {
            savedFingerprint = sp.getString("sig_fp_" + packageName, null);
            savedAuthor = sp.getString("sig_auth_" + packageName, null);
        }

        lastSignatureResult = ApkSignatureVerifier.verifyContinuity(currentCert, installedCert, savedFingerprint, savedAuthor);
        hasSignatureMismatch = lastSignatureResult.isMismatch;

        layoutSignatureResult.setVisibility(View.VISIBLE);
        switch (lastSignatureResult.status) {
            case MATCH_INSTALLED:
                layoutSignatureResult.setBackgroundColor(Color.parseColor("#f1f8e9")); // Light Green
                txtSignatureResult.setTextColor(Color.parseColor("#1b5e20")); // Dark Green
                txtSignatureResult.setText(getString(R.string.sig_verified_installed, (packageName != null ? packageName : "app"))
                        + "\nAuthor: " + currentCert.getDisplayAuthor()
                        + "\nSHA-256: " + currentCert.sha256Fingerprint);
                break;
            case MATCH_PREVIOUS:
                layoutSignatureResult.setBackgroundColor(Color.parseColor("#f1f8e9")); // Light Green
                txtSignatureResult.setTextColor(Color.parseColor("#1b5e20"));
                txtSignatureResult.setText(getString(R.string.sig_verified_previous)
                        + "\nAuthor: " + currentCert.getDisplayAuthor()
                        + "\nSHA-256: " + currentCert.sha256Fingerprint);
                break;
            case FIRST_TIME:
                layoutSignatureResult.setBackgroundColor(Color.parseColor("#f5f7f9")); // Neutral
                txtSignatureResult.setTextColor(Color.parseColor("#333333"));
                txtSignatureResult.setText(getString(R.string.sig_first_time, currentCert.getDisplayAuthor())
                        + "\nSHA-256: " + currentCert.sha256Fingerprint);
                saveSignatureRecord(packageName, currentCert);
                break;
            case MISMATCH_INSTALLED:
                layoutSignatureResult.setBackgroundColor(Color.parseColor("#ffebee")); // Light Red
                txtSignatureResult.setTextColor(Color.parseColor("#b71c1c")); // Dark Red
                txtSignatureResult.setText(getString(R.string.sig_mismatch_installed,
                        (packageName != null ? packageName : "app"),
                        (installedCert != null ? installedCert.sha256Fingerprint : "Unknown"),
                        currentCert.sha256Fingerprint));
                break;
            case MISMATCH_PREVIOUS:
                layoutSignatureResult.setBackgroundColor(Color.parseColor("#ffebee")); // Light Red
                txtSignatureResult.setTextColor(Color.parseColor("#b71c1c")); // Dark Red
                txtSignatureResult.setText(getString(R.string.sig_mismatch_previous,
                        savedFingerprint, currentCert.sha256Fingerprint));
                break;
            default:
                layoutSignatureResult.setVisibility(View.GONE);
                break;
        }
    }

    private void saveSignatureRecord(String packageName, ApkSignatureVerifier.CertInfo cert) {
        if (packageName == null || cert == null) return;
        SharedPreferences sp = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        sp.edit()
                .putString("sig_fp_" + packageName, cert.sha256Fingerprint)
                .putString("sig_auth_" + packageName, cert.getDisplayAuthor())
                .commit();
    }

    private void updatePresetDownloadRecord(File destinationFile, String templatePattern, String finalUrl,
                                            String version) {
        if (destinationFile == null || !destinationFile.exists()) return;
        String rawUrl = templatePattern != null ? templatePattern : finalUrl;
        if (templatePattern == null) templatePattern = finalUrl;

        for (PresetItem p : presetList) {
            if (p.url.equals(templatePattern) || p.url.equals(rawUrl) || p.url.equals(finalUrl)) {
                p.lastFileName = destinationFile.getName();
                p.lastFileSize = destinationFile.length();
                p.lastDownloadedAt = System.currentTimeMillis();
                p.lastSha256 = lastComputedSha256;
                if (lastSignatureResult != null && lastSignatureResult.currentCert != null) {
                    p.lastSigFingerprint = lastSignatureResult.currentCert.sha256Fingerprint;
                    p.lastAuthor = lastSignatureResult.currentCert.getDisplayAuthor();
                }
                p.lastVersion = version != null ? version : extractVersionInfo(destinationFile);
                savePresets();
                renderPresets();
                break;
            }
        }
    }

    private String extractVersionInfo(File file) {
        if (variableInputs.containsKey("1")) {
            EditText et = variableInputs.get("1");
            if (et != null) {
                String v = et.getText().toString().trim();
                if (!v.isEmpty()) return v;
            }
        }
        if (variableInputs.containsKey("version")) {
            EditText et = variableInputs.get("version");
            if (et != null) {
                String v = et.getText().toString().trim();
                if (!v.isEmpty()) return v;
            }
        }
        try {
            PackageManager pm = getPackageManager();
            PackageInfo pi = pm.getPackageArchiveInfo(file.getAbsolutePath(), 0);
            if (pi != null && pi.versionName != null) {
                return pi.versionName;
            }
        } catch (Exception ignored) {}
        return null;
    }

    /**
     * An upgrade needs no question when the option is on, the file is signed with the same key as
     * the installed app, its checksum raised no warning (checked by the caller), and its version
     * is newer. Android 12+ may then install it with no screen at all (see SessionInstaller);
     * otherwise the system installer opens straight away and needs one tap.
     * Returns false when this is not such an upgrade.
     */
    private boolean startUpgrade(File apkFile) {
        if (!chkAutoUpgrade.isChecked() || lastSignatureResult == null
                || lastSignatureResult.status != ApkSignatureVerifier.Status.MATCH_INSTALLED) {
            return false;
        }
        PackageInfo archive;
        PackageInfo installed;
        try {
            PackageManager pm = getPackageManager();
            archive = pm.getPackageArchiveInfo(apkFile.getAbsolutePath(), 0);
            if (archive == null) return false;
            installed = pm.getPackageInfo(archive.packageName, 0);
        } catch (Exception e) {
            return false;
        }
        if (archive.versionCode <= installed.versionCode) return false;
        String label = installed.applicationInfo != null
                ? String.valueOf(installed.applicationInfo.loadLabel(getPackageManager())) : archive.packageName;
        Toast.makeText(this, getString(R.string.upgrade_started, label,
                archive.versionName != null ? archive.versionName : String.valueOf(archive.versionCode)),
                Toast.LENGTH_SHORT).show();
        if (!SessionInstaller.start(this, apkFile, archive.packageName, label, true)) {
            launchViewInstaller(apkFile);
        }
        return true;
    }

    private void promptAutoInstall(final File apkFile) {
        new AlertDialog.Builder(this)
                .setTitle("Download Complete")
                .setMessage("Downloaded " + apkFile.getName() + ".\nInstall now?")
                .setPositiveButton("Install", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        launchApkInstaller(apkFile);
                    }
                })
                .setNegativeButton("Later", null)
                .show();
    }

    /** The system installer, with its confirmation screen; see SessionInstaller for why a session. */
    private void launchApkInstaller(File apkFile) {
        String pkg = getPackageNameFromArchive(apkFile);
        String label = pkg != null ? pkg : apkFile.getName();
        try {
            PackageInfo pi = getPackageManager().getPackageArchiveInfo(apkFile.getAbsolutePath(), 0);
            if (pi != null && pi.applicationInfo != null) {
                pi.applicationInfo.sourceDir = apkFile.getAbsolutePath();
                pi.applicationInfo.publicSourceDir = apkFile.getAbsolutePath();
                label = String.valueOf(pi.applicationInfo.loadLabel(getPackageManager()));
            }
        } catch (Exception ignored) {
        }
        if (!SessionInstaller.start(this, apkFile, pkg, label, false)) {
            launchViewInstaller(apkFile);
        }
    }

    /** Android 4.4 and older, or when a session cannot start: ACTION_VIEW on the file. */
    private void launchViewInstaller(File apkFile) {
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(Uri.fromFile(apkFile), "application/vnd.android.package-archive");
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
        } catch (Exception e) {
            Toast.makeText(this, "Could not open installer: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        char unit = "KMGTPE".charAt(exp - 1);
        return String.format("%.1f %sB", bytes / Math.pow(1024, exp), unit);
    }
}
