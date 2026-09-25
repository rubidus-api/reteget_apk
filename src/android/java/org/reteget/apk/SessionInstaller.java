package org.reteget.apk;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.os.Build;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;

/**
 * Installs an APK through a PackageInstaller session (Android 5+), and upgrades an installed app
 * without the confirmation screen where Android allows it.
 *
 * <p>A session, not ACTION_VIEW on the file: the system installer stopped accepting file://
 * addresses (Android 10 has no activity for them), and a session also records ReteGet as the
 * app's installer, which the no-confirmation upgrade below requires.
 *
 * <p>Android 12 (API 31) lets an installer update an app with no user action when: the
 * installer holds REQUEST_INSTALL_PACKAGES (and, from Android 13, declares
 * UPDATE_PACKAGES_WITHOUT_USER_ACTION); it is the app's installer of record, or the app is
 * the installer itself; and the new APK targets a recent enough API level. When any of that is
 * not met, the system answers "pending user action" and this shows its confirmation screen, so
 * the worst case is the ordinary one-tap install. Older Android never allows it.
 *
 * <p>PackageInstaller is reached by reflection because the app compiles against API 19; below
 * API 21 none of it is called.
 */
public final class SessionInstaller {

    static final String ACTION_RESULT = "com.reteget.INSTALL_RESULT";
    static final String EXTRA_LABEL = "com.reteget.LABEL";

    private static final String EXTRA_STATUS = "android.content.pm.extra.STATUS";
    private static final String EXTRA_STATUS_MESSAGE = "android.content.pm.extra.STATUS_MESSAGE";
    private static final int STATUS_PENDING_USER_ACTION = -1;
    private static final int STATUS_SUCCESS = 0;
    private static final int MODE_FULL_INSTALL = 1;
    private static final int USER_ACTION_REQUIRED = 1;
    private static final int USER_ACTION_NOT_REQUIRED = 2;
    private static final int FLAG_MUTABLE = 0x02000000;

    private SessionInstaller() {}

    public static boolean isSupported() {
        return Build.VERSION.SDK_INT >= 21;
    }

    /** Whether Android may skip the confirmation for an upgrade (it still decides). */
    public static boolean canSkipConfirmation() {
        return Build.VERSION.SDK_INT >= 31;
    }

    /**
     * Hands the APK to a PackageInstaller session; with {@code noConfirmation} it asks Android to
     * skip the confirmation screen (see the class notes). Returns false when the session could
     * not be started; the caller then falls back to the installer screen.
     */
    public static boolean start(Context ctx, File apk, String packageName, String label,
                                boolean noConfirmation) {
        if (!isSupported()) return false;
        Object session = null;
        try {
            Object pm = ctx.getPackageManager();
            Object installer = pm.getClass().getMethod("getPackageInstaller").invoke(pm);
            Class<?> paramsClass = Class.forName("android.content.pm.PackageInstaller$SessionParams");
            Object params = paramsClass.getConstructor(int.class).newInstance(MODE_FULL_INSTALL);
            if (canSkipConfirmation()) {
                paramsClass.getMethod("setRequireUserAction", int.class).invoke(params,
                        noConfirmation ? USER_ACTION_NOT_REQUIRED : USER_ACTION_REQUIRED);
            }
            if (packageName != null) {
                paramsClass.getMethod("setAppPackageName", String.class).invoke(params, packageName);
            }
            paramsClass.getMethod("setSize", long.class).invoke(params, apk.length());
            int id = (Integer) installer.getClass().getMethod("createSession", paramsClass)
                    .invoke(installer, params);
            session = installer.getClass().getMethod("openSession", int.class).invoke(installer, id);
            Class<?> sc = session.getClass();
            OutputStream out = (OutputStream) sc.getMethod("openWrite", String.class, long.class, long.class)
                    .invoke(session, "base.apk", 0L, apk.length());
            InputStream in = new FileInputStream(apk);
            try {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                sc.getMethod("fsync", OutputStream.class).invoke(session, out);
            } finally {
                in.close();
                out.close();
            }
            Intent result = new Intent(ACTION_RESULT);
            result.setClass(ctx, Result.class);
            result.putExtra(EXTRA_LABEL, label);
            PendingIntent pending = PendingIntent.getBroadcast(ctx, id, result,
                    PendingIntent.FLAG_UPDATE_CURRENT | FLAG_MUTABLE);
            sc.getMethod("commit", IntentSender.class).invoke(session, pending.getIntentSender());
            return true;
        } catch (Throwable t) {
            if (session != null) {
                try {
                    Method abandon = session.getClass().getMethod("abandon");
                    abandon.invoke(session);
                } catch (Throwable ignored) {
                }
            }
            return false;
        } finally {
            if (session != null) {
                try {
                    session.getClass().getMethod("close").invoke(session);
                } catch (Throwable ignored) {
                }
            }
        }
    }

    /** The session's answer: done, needs the user's confirmation, or failed. */
    public static final class Result extends BroadcastReceiver {
        @Override
        public void onReceive(Context ctx, Intent intent) {
            int status = intent.getIntExtra(EXTRA_STATUS, Integer.MIN_VALUE);
            String label = intent.getStringExtra(EXTRA_LABEL);
            if (label == null) label = "the app";
            if (status == STATUS_PENDING_USER_ACTION) {
                Intent confirm = (Intent) intent.getParcelableExtra(Intent.EXTRA_INTENT);
                if (confirm != null) {
                    confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    try {
                        ctx.startActivity(confirm);
                    } catch (Exception e) {
                        toast(ctx, ctx.getString(R.string.install_failed, label, e.getMessage()));
                    }
                }
            } else if (status == STATUS_SUCCESS) {
                toast(ctx, ctx.getString(R.string.install_done, label));
            } else {
                String msg = intent.getStringExtra(EXTRA_STATUS_MESSAGE);
                toast(ctx, ctx.getString(R.string.install_failed, label, msg != null ? msg : "status " + status));
            }
        }

        private static void toast(Context ctx, String text) {
            Toast.makeText(ctx, text, Toast.LENGTH_LONG).show();
        }
    }
}
