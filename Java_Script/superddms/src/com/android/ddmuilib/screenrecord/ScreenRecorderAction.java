/*
 * Copyright (C) 2013 The Android Open Source Project
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

package com.android.ddmuilib.screenrecord;

import com.android.annotations.NonNull;
import com.android.annotations.Nullable;
import com.android.ddmlib.CollectingOutputReceiver;
import com.android.ddmlib.IDevice;
import com.android.ddmlib.ScreenRecorderOptions;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.dialogs.ProgressMonitorDialog;
import org.eclipse.jface.operation.IRunnableWithProgress;
import org.eclipse.jface.window.Window;
import org.eclipse.swt.widgets.Shell;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class ScreenRecorderAction {
    private static final String TITLE = "Screen Recorder";
    private static final String REMOTE_PATH = "/sdcard/ddmsrec.mp4";

    private final Shell mParentShell;
    private final IDevice mDevice;

    public ScreenRecorderAction(Shell parent, IDevice device) {
        mParentShell = parent;
        mDevice = device;
    }

    public void performAction() {
        ScreenRecorderOptionsDialog optionsDialog = new ScreenRecorderOptionsDialog(mParentShell);
        if (optionsDialog.open() == Window.CANCEL) {
            return;
        }

        final ScreenRecorderOptions options = new ScreenRecorderOptions.Builder()
                .setBitRate(optionsDialog.getBitRate())
                .setSize(optionsDialog.getWidth(), optionsDialog.getHeight())
                .build();

        final CountDownLatch latch = new CountDownLatch(1);
        final CollectingOutputReceiver receiver = new CollectingOutputReceiver(latch);

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    mDevice.startScreenRecorder(REMOTE_PATH, options, receiver);
                } catch (Exception e) {
                    showError("Unexpected error while launching screenrecorder", e);
                    latch.countDown();
                }
            }
        }, "Screen Recorder").start();

        try {
            new ProgressMonitorDialog(mParentShell).run(true, true, new IRunnableWithProgress() {
                @Override
                public void run(IProgressMonitor monitor)
                        throws InvocationTargetException, InterruptedException {
                    int timeInSecond = 0;
                    monitor.beginTask("Recording...", IProgressMonitor.UNKNOWN);

                    while (true) {
                        // Wait for a second to see if the command has completed
                        if (latch.await(1, TimeUnit.SECONDS)) {
                            break;
                        }

                        // update recording time in second
                        monitor.subTask(String.format("Recording...%d seconds elapsed", timeInSecond++));

                        // If not, check if user has cancelled
                        if (monitor.isCanceled()) {
                            receiver.cancel();

                            monitor.subTask("Stopping...");

                            // wait for an additional second to make sure that the command
                            // completed and screenrecorder finishes writing the output
                            latch.await(1, TimeUnit.SECONDS);
                            break;
                        }
                    }
                }
            });
        } catch (InvocationTargetException e) {
            showError("Unexpected error while recording: ", e.getTargetException());
            return;
        } catch (InterruptedException ignored) {
        }

        try {
            mDevice.pullFile(REMOTE_PATH, optionsDialog.getDestination().getAbsolutePath());
        } catch (Exception e) {
            showError("Unexpected error while copying video recording from device", e);
        }

        MessageDialog.openInformation(mParentShell, TITLE, "Screen recording saved at " +
                optionsDialog.getDestination().getAbsolutePath());
    }

    private void showError(@NonNull final String message, @Nullable final Throwable e) {
        mParentShell.getDisplay().asyncExec(new Runnable() {
            @Override
            public void run() {
                String msg = message;
                if (e != null) {
                    msg += e.getLocalizedMessage() != null ? ": " + e.getLocalizedMessage() : "";
                }
                MessageDialog.openError(mParentShell, TITLE, msg);
            }
        });

    }
}
