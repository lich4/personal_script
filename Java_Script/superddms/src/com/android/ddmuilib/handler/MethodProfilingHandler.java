/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.ddmuilib.handler;

import com.android.ddmlib.Client;
import com.android.ddmlib.ClientData.IMethodProfilingHandler;
import com.android.ddmlib.DdmConstants;
import com.android.ddmlib.IDevice;
import com.android.ddmlib.Log;
import com.android.ddmlib.SyncException;
import com.android.ddmlib.SyncService;
import com.android.ddmlib.SyncService.ISyncProgressMonitor;
import com.android.ddmlib.TimeoutException;
import com.android.ddmuilib.DdmUiPreferences;
import com.android.ddmuilib.SyncProgressHelper;
import com.android.ddmuilib.SyncProgressHelper.SyncRunnable;
import com.android.ddmuilib.console.DdmConsole;

import org.eclipse.swt.widgets.Shell;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;

/**
 * Handler for Method tracing.
 * This will pull the trace file into a temp file and launch traceview.
 */
public class MethodProfilingHandler extends BaseFileHandler
        implements IMethodProfilingHandler {

    public MethodProfilingHandler(Shell parentShell) {
        super(parentShell);
    }

    @Override
    protected String getDialogTitle() {
        return "Method Profiling Error";
    }

    @Override
    public void onStartFailure(final Client client, final String message) {
        displayErrorInUiThread(
                "Unable to create Method Profiling file for application '%1$s'\n\n%2$s" +
                "Check logcat for more information.",
                client.getClientData().getClientDescription(),
                message != null ? message + "\n\n" : "");
    }

    @Override
    public void onEndFailure(final Client client, final String message) {
        displayErrorInUiThread(
                "Unable to finish Method Profiling for application '%1$s'\n\n%2$s" +
                "Check logcat for more information.",
                client.getClientData().getClientDescription(),
                message != null ? message + "\n\n" : "");
    }

    @Override
    public void onSuccess(final String remoteFilePath, final Client client) {
        mParentShell.getDisplay().asyncExec(new Runnable() {
            @Override
            public void run() {
                if (remoteFilePath == null) {
                    displayErrorFromUiThread(
                            "Unable to download trace file: unknown file name.\n" +
                            "This can happen if you disconnected the device while recording the trace.");
                    return;
                }

                final IDevice device = client.getDevice();
                try {
                    // get the sync service to pull the HPROF file
                    final SyncService sync = client.getDevice().getSyncService();
                    if (sync != null) {
                        pullAndOpen(sync, remoteFilePath);
                    } else {
                        displayErrorFromUiThread(
                                "Unable to download trace file from device '%1$s'.",
                                device.getSerialNumber());
                    }
                } catch (Exception e) {
                    displayErrorFromUiThread("Unable to download trace file from device '%1$s'.",
                            device.getSerialNumber());
                }
            }

        });
    }

    @Override
    public void onSuccess(byte[] data, final Client client) {
        try {
            File tempFile = saveTempFile(data, DdmConstants.DOT_TRACE);
            open(tempFile.getAbsolutePath());
        } catch (IOException e) {
            String errorMsg = e.getMessage();
            displayErrorInUiThread(
                    "Failed to save trace data into temp file%1$s",
                    errorMsg != null ? ":\n" + errorMsg : ".");
        }
    }

    /**
     * pulls and open a file. This is run from the UI thread.
     */
    private void pullAndOpen(final SyncService sync, final String remoteFilePath)
            throws InvocationTargetException, InterruptedException, IOException {
        // get a temp file
        File temp = File.createTempFile("android", DdmConstants.DOT_TRACE); //$NON-NLS-1$
        final String tempPath = temp.getAbsolutePath();

        // pull the file
        try {
            SyncProgressHelper.run(new SyncRunnable() {
                    @Override
                    public void run(ISyncProgressMonitor monitor)
                            throws SyncException, IOException, TimeoutException {
                        sync.pullFile(remoteFilePath, tempPath, monitor);
                    }

                    @Override
                    public void close() {
                        sync.close();
                    }
                },
                String.format("Pulling %1$s from the device", remoteFilePath), mParentShell);

            // open the temp file in traceview
            open(tempPath);
        } catch (SyncException e) {
            if (e.wasCanceled() == false) {
                displayErrorFromUiThread("Unable to download trace file:\n\n%1$s", e.getMessage());
            }
        } catch (TimeoutException e) {
            displayErrorFromUiThread("Unable to download trace file:\n\ntimeout");
        }
    }

    protected void open(String tempPath) {
        // now that we have the file, we need to launch traceview
        String[] command = new String[2];
        command[0] = DdmUiPreferences.getTraceview();
        command[1] = tempPath;

        try {
            final Process p = Runtime.getRuntime().exec(command);

            // create a thread for the output
            new Thread("Traceview output") {
                @Override
                public void run() {
                    // create a buffer to read the stderr output
                    InputStreamReader is = new InputStreamReader(p.getErrorStream());
                    BufferedReader resultReader = new BufferedReader(is);

                    // read the lines as they come. if null is returned, it's
                    // because the process finished
                    try {
                        while (true) {
                            String line = resultReader.readLine();
                            if (line != null) {
                                DdmConsole.printErrorToConsole("Traceview: " + line);
                            } else {
                                break;
                            }
                        }
                        // get the return code from the process
                        p.waitFor();
                    } catch (Exception e) {
                        Log.e("traceview", e);
                    }
                }
            }.start();
        } catch (IOException e) {
            Log.e("traceview", e);
        }
    }
}
