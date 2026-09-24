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
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.reteget.core.ChecksumVerifier;
import org.reteget.core.DownloadEngine;
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

    // Bottom presets section
    private Button btnAddPreset;
    private TextView txtNoPresets;
    private LinearLayout layoutPresetsList;

    private List<String> presetList = new ArrayList<String>();
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

        btnAddPreset = (Button) findViewById(R.id.btn_add_preset);
        txtNoPresets = (TextView) findViewById(R.id.txt_no_presets);
        layoutPresetsList = (LinearLayout) findViewById(R.id.layout_presets_list);
    }

    private void setupPresets() {
        loadPresets();
        renderPresets();
        if (!presetList.isEmpty() && editUrl.getText().toString().trim().isEmpty()) {
            String initial = presetList.get(0);
            editUrl.setText(initial);
            editUrl.setSelection(initial.length());
        }

        btnAddPreset.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String url = editUrl.getText().toString().trim();
                if (url.isEmpty()) {
                    Toast.makeText(MainActivity.this, "URL is empty", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (!presetList.contains(url)) {
                    presetList.add(url);
                    savePresets();
                    renderPresets();
                    Toast.makeText(MainActivity.this, R.string.toast_preset_saved, Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(MainActivity.this, R.string.toast_preset_exists, Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    private void renderPresets() {
        layoutPresetsList.removeAllViews();
        if (presetList.isEmpty()) {
            txtNoPresets.setVisibility(View.VISIBLE);
            return;
        }
        txtNoPresets.setVisibility(View.GONE);

        LayoutInflater inflater = LayoutInflater.from(this);
        for (int i = 0; i < presetList.size(); i++) {
            final String url = presetList.get(i);
            View row = inflater.inflate(R.layout.item_preset, layoutPresetsList, false);

            TextView txtUrl = (TextView) row.findViewById(R.id.txt_preset_url);
            txtUrl.setText(url);

            Button btnUse = (Button) row.findViewById(R.id.btn_use);
            Button btnDelete = (Button) row.findViewById(R.id.btn_delete);

            View.OnClickListener useListener = new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    editUrl.setText(url);
                    editUrl.setSelection(url.length());
                    scrollView.smoothScrollTo(0, 0);
                    Toast.makeText(MainActivity.this, R.string.toast_preset_loaded, Toast.LENGTH_SHORT).show();
                }
            };

            btnUse.setOnClickListener(useListener);
            row.setOnClickListener(useListener);

            btnDelete.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    presetList.remove(url);
                    savePresets();
                    renderPresets();
                    Toast.makeText(MainActivity.this, R.string.toast_preset_removed, Toast.LENGTH_SHORT).show();
                }
            });

            layoutPresetsList.addView(row);
        }
    }

    private void loadPresets() {
        presetList.clear();
        SharedPreferences sp = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String raw = sp.getString(KEY_PRESETS, null);
        if (raw != null && !raw.trim().isEmpty()) {
            String[] items = raw.split("\n");
            for (String item : items) {
                String trimmed = item.trim();
                if (!trimmed.isEmpty()) {
                    presetList.add(trimmed);
                }
            }
        }

        if (presetList.isEmpty()) {
            // Built-in defaults
            presetList.add("https://github.com/f-droid/fdroidclient/releases/download/{1}/F-Droid.apk");
            presetList.add("https://archive.org/download/{1}/{2}.apk");
            presetList.add("http://192.168.1.100:8000/apks/{1}.apk");
            savePresets();
        }
    }

    private void savePresets() {
        SharedPreferences sp = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        StringBuilder sb = new StringBuilder();
        for (String url : presetList) {
            sb.append(url).append("\n");
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
                            if (!hasChecksumMismatch) {
                                promptAutoInstall(destinationFile);
                            }
                        } else {
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
                        new AlertDialog.Builder(MainActivity.this)
                                .setTitle(R.string.dialog_mismatch_title)
                                .setMessage(R.string.dialog_mismatch_msg)
                                .setPositiveButton(R.string.dialog_btn_install_anyway, new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        launchApkInstaller(lastDownloadedFile);
                                    }
                                })
                                .setNegativeButton("Cancel", null)
                                .show();
                    } else {
                        launchApkInstaller(lastDownloadedFile);
                    }
                } else {
                    Toast.makeText(MainActivity.this, "APK file not found", Toast.LENGTH_SHORT).show();
                }
            }
        });
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
