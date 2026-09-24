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
import org.reteget.core.PresetItem;
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

    private ScrollView scrollView;
    private EditText editUrl;
    private LinearLayout layoutVariables;
    private LinearLayout variablesFields;
    private TextView txtResolvedPreview;

    private EditText editExpectedChecksum;
    private Button btnClearChecksum;
    private CheckBox chkInsecureSsl;

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
    private CheckBox chkPresetSelectAll;
    private Button btnDeleteSelected;
    private boolean isUpdatingSelectAll = false;

    private List<PresetItem> presetList = new ArrayList<PresetItem>();
    private Map<String, EditText> variableInputs = new HashMap<String, EditText>();
    private UrlTemplate currentTemplate;

    private DownloadEngine downloadEngine;
    private File lastDownloadedFile;
    private String lastComputedSha256 = null;
    private boolean hasChecksumMismatch = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Bypass FileUriExposedException on Android 7.0+ (API 24+)
        disableStrictModeFileUriExposure();

        // Initialize TLS 1.2 and bundled modern Root CAs
        initTlsCerts();

        setContentView(R.layout.activity_main);

        bindViews();
        setupPresets();
        setupUrlWatcher();
        setupChecksumControls();
        setupDownloadControls();
        setupInstallControl();
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

        btnDownload = (Button) findViewById(R.id.btn_download);
        btnCancel = (Button) findViewById(R.id.btn_cancel);
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
        chkPresetSelectAll = (CheckBox) findViewById(R.id.chk_preset_select_all);
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
                String url = editUrl.getText().toString().trim();
                if (url.isEmpty()) {
                    Toast.makeText(MainActivity.this, "URL is empty", Toast.LENGTH_SHORT).show();
                    return;
                }
                PresetItem candidate = new PresetItem(url);
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
        });

        chkPresetSelectAll.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isUpdatingSelectAll) return;
                for (PresetItem p : presetList) {
                    p.isSelected = isChecked;
                }
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
                                isUpdatingSelectAll = true;
                                chkPresetSelectAll.setChecked(false);
                                isUpdatingSelectAll = false;
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

        int selectedCount = 0;
        for (PresetItem p : presetList) {
            if (p.isSelected) selectedCount++;
        }

        if (selectedCount > 0) {
            btnDeleteSelected.setVisibility(View.VISIBLE);
            btnDeleteSelected.setText(getString(R.string.btn_delete_selected, selectedCount));
        } else {
            btnDeleteSelected.setVisibility(View.GONE);
        }

        isUpdatingSelectAll = true;
        chkPresetSelectAll.setChecked(selectedCount == presetList.size() && !presetList.isEmpty());
        isUpdatingSelectAll = false;

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

            View contentLayout = row.findViewById(R.id.layout_preset_content);
            TextView txtUrl = (TextView) row.findViewById(R.id.txt_preset_url);
            TextView txtMeta = (TextView) row.findViewById(R.id.txt_preset_meta);

            txtUrl.setText(item.url);
            txtMeta.setText(item.getMetadataSummary());

            View.OnClickListener useListener = new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    selectAndLoadPreset(item, true);
                }
            };

            contentLayout.setOnClickListener(useListener);
            txtUrl.setOnClickListener(useListener);

            Button btnUse = (Button) row.findViewById(R.id.btn_use);
            btnUse.setOnClickListener(useListener);

            Button btnEdit = (Button) row.findViewById(R.id.btn_edit);
            btnEdit.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    promptEditPresetDialog(item);
                }
            });

            Button btnMoveUp = (Button) row.findViewById(R.id.btn_move_up);
            if (index == 0) {
                btnMoveUp.setEnabled(false);
            } else {
                btnMoveUp.setEnabled(true);
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

            Button btnMoveDown = (Button) row.findViewById(R.id.btn_move_down);
            if (index == presetList.size() - 1) {
                btnMoveDown.setEnabled(false);
            } else {
                btnMoveDown.setEnabled(true);
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

            Button btnDelete = (Button) row.findViewById(R.id.btn_delete);
            btnDelete.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    promptDeleteSinglePresetDialog(item, index);
                }
            });

            layoutPresetsList.addView(row);
        }
    }

    private void updateBatchSelectionState() {
        int selectedCount = 0;
        for (PresetItem p : presetList) {
            if (p.isSelected) selectedCount++;
        }
        if (selectedCount > 0) {
            btnDeleteSelected.setVisibility(View.VISIBLE);
            btnDeleteSelected.setText(getString(R.string.btn_delete_selected, selectedCount));
        } else {
            btnDeleteSelected.setVisibility(View.GONE);
        }
        isUpdatingSelectAll = true;
        chkPresetSelectAll.setChecked(selectedCount == presetList.size() && !presetList.isEmpty());
        isUpdatingSelectAll = false;
    }

    private void selectAndLoadPreset(PresetItem item, boolean showToast) {
        editUrl.setText(item.url);
        editUrl.setSelection(item.url.length());
        scrollView.smoothScrollTo(0, 0);
        if (showToast) {
            Toast.makeText(MainActivity.this, R.string.toast_preset_loaded, Toast.LENGTH_SHORT).show();
        }
    }

    private void promptEditPresetDialog(final PresetItem item) {
        final EditText input = new EditText(this);
        input.setText(item.url);
        input.setSelection(item.url.length());

        new AlertDialog.Builder(this)
                .setTitle(R.string.dialog_edit_preset_title)
                .setView(input)
                .setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        String newUrl = input.getText().toString().trim();
                        if (!newUrl.isEmpty()) {
                            item.url = newUrl;
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

        if (presetList.isEmpty()) {
            // Built-in defaults
            presetList.add(new PresetItem("https://github.com/f-droid/fdroidclient/releases/download/{1}/F-Droid.apk"));
            presetList.add(new PresetItem("https://archive.org/download/{1}/{2}.apk"));
            presetList.add(new PresetItem("http://192.168.1.100:8000/apks/{1}.apk"));
            savePresets();
        }
    }

    private void savePresets() {
        SharedPreferences sp = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        StringBuilder sb = new StringBuilder();
        for (PresetItem p : presetList) {
            sb.append(p.toJson()).append("\n");
        }
        sp.edit().putString(KEY_PRESETS, sb.toString()).commit();
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
                if (s.length() > 0) {
                    btnClearChecksum.setVisibility(View.VISIBLE);
                } else {
                    btnClearChecksum.setVisibility(View.GONE);
                }
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
                if (downloadEngine != null) {
                    downloadEngine.cancel();
                    btnCancel.setEnabled(false);
                    txtStatus.setText("Cancelling download…");
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

        File destDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        if (destDir == null || !destDir.exists()) {
            destDir = new File(Environment.getExternalStorageDirectory(), "Download");
        }
        if (!destDir.exists()) {
            destDir.mkdirs();
        }

        btnDownload.setEnabled(false);
        btnCancel.setEnabled(true);
        btnInstall.setVisibility(View.GONE);
        layoutChecksumResult.setVisibility(View.GONE);
        hasChecksumMismatch = false;
        layoutSignatureResult.setVisibility(View.GONE);
        hasSignatureMismatch = false;
        lastSignatureResult = null;

        progressBar.setVisibility(View.VISIBLE);
        progressBar.setIndeterminate(true);
        txtProgressDetails.setVisibility(View.VISIBLE);
        txtProgressDetails.setText("");
        txtStatus.setText("Connecting…");

        downloadEngine = new DownloadEngine();
        final boolean insecure = chkInsecureSsl.isChecked();

        downloadEngine.download(url, destDir, insecure, new DownloadEngine.Listener() {
            @Override
            public void onStart(final String filename, final long totalBytes) {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (totalBytes > 0) {
                            progressBar.setIndeterminate(false);
                            progressBar.setMax(100);
                            progressBar.setProgress(0);
                            txtStatus.setText("Downloading " + filename + " (" + formatBytes(totalBytes) + ")");
                        } else {
                            progressBar.setIndeterminate(true);
                            txtStatus.setText("Downloading " + filename + " (stream)");
                        }
                    }
                });
            }

            @Override
            public void onProgress(final long bytesRead, final long totalBytes, final int percent, final long bytesPerSec) {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (percent >= 0) {
                            progressBar.setIndeterminate(false);
                            progressBar.setProgress(percent);
                        }
                        String details = formatBytes(bytesRead)
                                + (totalBytes > 0 ? " / " + formatBytes(totalBytes) + " (" + percent + "%)" : "")
                                + (bytesPerSec > 0 ? " — " + formatBytes(bytesPerSec) + "/s" : "");
                        txtProgressDetails.setText(details);
                    }
                });
            }

            @Override
            public void onComplete(final File destinationFile) {
                // Compute hash off the main UI thread
                try {
                    lastComputedSha256 = ChecksumVerifier.computeHash(destinationFile, "SHA-256");
                } catch (Exception e) {
                    lastComputedSha256 = "Error computing hash: " + e.getMessage();
                }

                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        lastDownloadedFile = destinationFile;
                        btnDownload.setEnabled(true);
                        btnCancel.setEnabled(false);
                        progressBar.setVisibility(View.GONE);
                        txtProgressDetails.setVisibility(View.GONE);
                        txtStatus.setText("Saved to: " + destinationFile.getAbsolutePath()
                                + " (" + formatBytes(destinationFile.length()) + ")");

                        String expected = editExpectedChecksum.getText().toString().trim();
                        verifyDownloadedFile(destinationFile, expected);

                        if (destinationFile.getName().toLowerCase().endsWith(".apk")) {
                            btnInstall.setVisibility(View.VISIBLE);
                            verifyApkSignature(destinationFile);
                            updatePresetDownloadRecord(destinationFile);
                            if (hasChecksumMismatch) {
                                // Keep visible for manual install button review
                            } else if (hasSignatureMismatch) {
                                promptSignatureMismatchDialog(destinationFile);
                            } else {
                                promptAutoInstall(destinationFile);
                            }
                        } else {
                            updatePresetDownloadRecord(destinationFile);
                            Toast.makeText(MainActivity.this, "File saved successfully", Toast.LENGTH_SHORT).show();
                        }
                    }
                });
            }

            @Override
            public void onError(final Exception ex) {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        btnDownload.setEnabled(true);
                        btnCancel.setEnabled(false);
                        progressBar.setVisibility(View.GONE);
                        txtProgressDetails.setVisibility(View.GONE);
                        txtStatus.setText("Download failed: " + ex.getMessage());
                        Toast.makeText(MainActivity.this, "Error: " + ex.getMessage(), Toast.LENGTH_LONG).show();
                    }
                });
            }

            @Override
            public void onCancel() {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        btnDownload.setEnabled(true);
                        btnCancel.setEnabled(false);
                        progressBar.setVisibility(View.GONE);
                        txtProgressDetails.setVisibility(View.GONE);
                        txtStatus.setText("Download cancelled.");
                    }
                });
            }
        });
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

    private void updatePresetDownloadRecord(File destinationFile) {
        if (destinationFile == null || !destinationFile.exists()) return;
        String rawUrl = editUrl.getText().toString().trim();
        String templatePattern = (currentTemplate != null) ? currentTemplate.getTemplate() : rawUrl;
        String finalUrl = getFinalDownloadUrl();

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
                p.lastVersion = extractVersionInfo(destinationFile);
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

    private void launchApkInstaller(File apkFile) {
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
