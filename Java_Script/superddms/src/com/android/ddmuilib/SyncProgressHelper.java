/*
 * Copyright (C) 2010 The Android Open Source Project
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

package com.android.ddmuilib;

import com.android.ddmlib.SyncException;
import com.android.ddmlib.SyncService;
import com.android.ddmlib.SyncService.ISyncProgressMonitor;
import com.android.ddmlib.TimeoutException;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.jface.dialogs.ProgressMonitorDialog;
import org.eclipse.jface.operation.IRunnableWithProgress;
import org.eclipse.swt.widgets.Shell;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

/**
 * Helper class to run a Sync in a {@link ProgressMonitorDialog}.
 */
public class SyncProgressHelper {

    /**
     * a runnable class run with an {@link ISyncProgressMonitor}.
     */
    public interface SyncRunnable {
        /** Runs the sync action */
        void run(ISyncProgressMonitor monitor) throws SyncException, IOException, TimeoutException;
        /** close the {@link SyncService} */
        void close();
    }

    /**
     * Runs a {@link SyncRunnable} in a {@link ProgressMonitorDialog}.
     * @param runnable The {@link SyncRunnable} to run.
     * @param progressMessage the message to display in the progress dialog
     * @param parentShell the parent shell for the progress dialog.
     *
     * @throws InvocationTargetException
     * @throws InterruptedException
     * @throws SyncException if an error happens during the push of the package on the device.
     * @throws IOException
     * @throws TimeoutException
     */
    public static void run(final SyncRunnable runnable, final String progressMessage,
            final Shell parentShell)
            throws InvocationTargetException, InterruptedException, SyncException, IOException,
            TimeoutException {

        final Exception[] result = new Exception[1];
        new ProgressMonitorDialog(parentShell).run(true, true, new IRunnableWithProgress() {
            @Override
            public void run(IProgressMonitor monitor) {
                try {
                    runnable.run(new SyncProgressMonitor(monitor, progressMessage));
                } catch (Exception e) {
                    result[0] = e;
                } finally {
                    runnable.close();
                }
            }
        });

        if (result[0] instanceof SyncException) {
            SyncException se = (SyncException)result[0];
            if (se.wasCanceled()) {
                // no need to throw this
                return;
            }
            throw se;
        }

        // just do some casting so that the method declaration matches what's thrown.
        if (result[0] instanceof TimeoutException) {
            throw (TimeoutException)result[0];
        }

        if (result[0] instanceof IOException) {
            throw (IOException)result[0];
        }

        if (result[0] instanceof RuntimeException) {
            throw (RuntimeException)result[0];
        }
    }
}
