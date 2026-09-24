package org.reteget.apk;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.StrictMode;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import org.reteget.core.DownloadEngine;
import org.reteget.core.TlsHelper;
import org.reteget.core.UrlTemplate;

import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class MainActivity extends Activity {

    private static final String PREFS_NAME = "reteget_prefs";
    private static final String KEY_PRESETS = "saved_presets";

    private Spinner spinnerPresets;
    private Button btnSavePreset;
    private Button btnDeletePreset;
    private EditText editUrl;
    private LinearLayout layoutVariables;
    private LinearLayout variablesFields;
    private TextView txtResolvedPreview;
    private CheckBox chkInsecureSsl;
    private Button btnDownload;
    private Button btnCancel;
    private ProgressBar progressBar;
    private TextView txtProgressDetails;
    private TextView txtStatus;
    private Button btnInstall;

    private List<String> presetList = new ArrayList<String>();
    private ArrayAdapter<String> presetAdapter;
    private Map<String, EditText> variableInputs = new HashMap<String, EditText>();
    private UrlTemplate currentTemplate;

    private DownloadEngine downloadEngine;
    private File lastDownloadedFile;

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
        spinnerPresets = (Spinner) findViewById(R.id.spinner_presets);
        btnSavePreset = (Button) findViewById(R.id.btn_save_preset);
        btnDeletePreset = (Button) findViewById(R.id.btn_delete_preset);
        editUrl = (EditText) findViewById(R.id.edit_url);
        layoutVariables = (LinearLayout) findViewById(R.id.layout_variables);
        variablesFields = (LinearLayout) findViewById(R.id.variables_fields);
        txtResolvedPreview = (TextView) findViewById(R.id.txt_resolved_preview);
        chkInsecureSsl = (CheckBox) findViewById(R.id.chk_insecure_ssl);
        btnDownload = (Button) findViewById(R.id.btn_download);
        btnCancel = (Button) findViewById(R.id.btn_cancel);
        progressBar = (ProgressBar) findViewById(R.id.progress_bar);
        txtProgressDetails = (TextView) findViewById(R.id.txt_progress_details);
        txtStatus = (TextView) findViewById(R.id.txt_status);
        btnInstall = (Button) findViewById(R.id.btn_install);
    }

    private void setupPresets() {
        loadPresets();
        presetAdapter = new ArrayAdapter<String>(this, android.R.layout.simple_spinner_item, presetList);
        presetAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerPresets.setAdapter(presetAdapter);

        spinnerPresets.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (position >= 0 && position < presetList.size()) {
                    String selected = presetList.get(position);
                    if (!selected.equals(editUrl.getText().toString())) {
                        editUrl.setText(selected);
                        editUrl.setSelection(selected.length());
                    }
                }
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });

        btnSavePreset.setOnClickListener(new View.OnClickListener() {
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
                    presetAdapter.notifyDataSetChanged();
                    spinnerPresets.setSelection(presetList.size() - 1);
                    Toast.makeText(MainActivity.this, "Preset saved", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(MainActivity.this, "Preset already exists", Toast.LENGTH_SHORT).show();
                }
            }
        });

        btnDeletePreset.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int pos = spinnerPresets.getSelectedItemPosition();
                if (pos >= 0 && pos < presetList.size()) {
                    presetList.remove(pos);
                    savePresets();
                    presetAdapter.notifyDataSetChanged();
                    if (!presetList.isEmpty()) {
                        spinnerPresets.setSelection(0);
                    } else {
                        editUrl.setText("");
                    }
                    Toast.makeText(MainActivity.this, "Preset removed", Toast.LENGTH_SHORT).show();
                }
            }
        });
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
        layoutVariables.setVisibility(View.VISIBLE);

        for (final String placeholder : placeholders) {
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setPadding(0, 4, 0, 4);

            TextView lbl = new TextView(this);
            lbl.setText("{" + placeholder + "}: ");
            lbl.setTextSize(13);
            lbl.setTextColor(0xFF333333);
            lbl.setPadding(0, 0, 8, 0);

            final EditText input = new EditText(this);
            input.setLayoutParams(new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.FILL_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT, 1.0f));
            input.setSingleLine(true);
            input.setTextSize(13);
            input.setHint("Value for " + placeholder);

            String prev = oldValues.get(placeholder);
            if (prev != null) {
                input.setText(prev);
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

            variableInputs.put(placeholder, input);
            row.addView(lbl);
            row.addView(input);
            variablesFields.addView(row);
        }

        updateResolvedPreview();
    }

    private void updateResolvedPreview() {
        if (currentTemplate == null || !currentTemplate.hasPlaceholders()) {
            txtResolvedPreview.setText("");
            return;
        }
        Map<String, String> map = new HashMap<String, String>();
        for (Map.Entry<String, EditText> entry : variableInputs.entrySet()) {
            map.put(entry.getKey(), entry.getValue().getText().toString().trim());
        }
        String resolved = currentTemplate.resolve(map);
        txtResolvedPreview.setText("Target: " + resolved);
    }

    private String getTargetUrl() {
        if (currentTemplate != null && currentTemplate.hasPlaceholders()) {
            Map<String, String> map = new HashMap<String, String>();
            for (Map.Entry<String, EditText> entry : variableInputs.entrySet()) {
                map.put(entry.getKey(), entry.getValue().getText().toString().trim());
            }
            return currentTemplate.resolve(map);
        }
        return editUrl.getText().toString().trim();
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
                    txtStatus.setText("Cancelling…");
                }
            }
        });
    }

    private void startDownload() {
        final String url = getTargetUrl();
        if (url == null || url.isEmpty()) {
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

                        if (destinationFile.getName().toLowerCase().endsWith(".apk")) {
                            btnInstall.setVisibility(View.VISIBLE);
                            promptAutoInstall(destinationFile);
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
                    launchApkInstaller(lastDownloadedFile);
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
