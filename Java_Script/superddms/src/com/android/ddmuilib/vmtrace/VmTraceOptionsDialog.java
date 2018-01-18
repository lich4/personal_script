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

package com.android.ddmuilib.vmtrace;

import org.eclipse.jface.dialogs.Dialog;
import org.eclipse.jface.dialogs.IDialogConstants;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;

/** Dialog that allows users to select between method tracing or sampler based profiling. */
public class VmTraceOptionsDialog extends Dialog {
    private static final int DEFAULT_SAMPLING_INTERVAL_US = 1000;

    // Static variables that maintain state across invocations of the dialog
    private static boolean sTracingEnabled = false;
    private static int sSamplingIntervalUs = DEFAULT_SAMPLING_INTERVAL_US;

    public VmTraceOptionsDialog(Shell parentShell) {
        super(parentShell);
    }

    @Override
    protected void configureShell(Shell newShell) {
        super.configureShell(newShell);
        newShell.setText("Profiling Options");
    }

    @Override
    protected Control createDialogArea(Composite shell) {
        int horizontalIndent = 30;

        Composite parent = (Composite) super.createDialogArea(shell);
        Composite c = new Composite(parent, SWT.NONE);
        c.setLayout(new GridLayout(2, false));
        c.setLayoutData(new GridData(GridData.FILL_BOTH));

        final Button useSamplingButton = new Button(c, SWT.RADIO);
        useSamplingButton.setText("Sample based profiling");
        useSamplingButton.setSelection(!sTracingEnabled);
        GridData gd = new GridData(GridData.HORIZONTAL_ALIGN_BEGINNING, GridData.VERTICAL_ALIGN_CENTER, true,
                true, 2, 1);
        useSamplingButton.setLayoutData(gd);

        Label l = new Label(c, SWT.NONE);
        l.setText("Sample based profiling works by interrupting the VM at a given frequency and \n"
                + "collecting the call stacks at that time. The overhead is proportional to the \n"
                + "sampling frequency.");
        gd = new GridData(GridData.HORIZONTAL_ALIGN_BEGINNING, GridData.VERTICAL_ALIGN_CENTER, true,
                true, 2, 1);
        gd.horizontalIndent = horizontalIndent;
        l.setLayoutData(gd);

        l = new Label(c, SWT.NONE);
        l.setText("Sampling frequency (microseconds): ");
        gd = new GridData(GridData.HORIZONTAL_ALIGN_BEGINNING, GridData.VERTICAL_ALIGN_END,
                false, true);
        gd.horizontalIndent = horizontalIndent;
        l.setLayoutData(gd);

        final Text samplingIntervalTextField = new Text(c, SWT.BORDER);
        gd = new GridData(GridData.HORIZONTAL_ALIGN_BEGINNING, GridData.VERTICAL_ALIGN_CENTER, true,
                true);
        gd.widthHint = 100;
        samplingIntervalTextField.setLayoutData(gd);
        samplingIntervalTextField.setEnabled(!sTracingEnabled);
        samplingIntervalTextField.setText(Integer.toString(sSamplingIntervalUs));
        samplingIntervalTextField.addModifyListener(new ModifyListener() {
            @Override
            public void modifyText(ModifyEvent modifyEvent) {
                int v = getIntegerValue(samplingIntervalTextField.getText());
                getButton(IDialogConstants.OK_ID).setEnabled(v > 0);
                sSamplingIntervalUs = v > 0 ? v : DEFAULT_SAMPLING_INTERVAL_US;
            }

            private int getIntegerValue(String text) {
                try {
                    return Integer.parseInt(text);
                } catch (NumberFormatException e) {
                    return -1;
                }
            }
        });

        final Button useTracingButton = new Button(c, SWT.RADIO);
        useTracingButton.setText("Trace based profiling");
        useTracingButton.setSelection(sTracingEnabled);
        gd = new GridData(GridData.HORIZONTAL_ALIGN_BEGINNING,
                GridData.VERTICAL_ALIGN_CENTER, true, true, 2, 1);
        useTracingButton.setLayoutData(gd);

        l = new Label(c, SWT.NONE);
        l.setText("Trace based profiling works by tracing the entry and exit of every method.\n"
                + "This captures the execution of all methods, no matter how small, and hence\n"
                + "has a high overhead.");
        gd = new GridData(GridData.HORIZONTAL_ALIGN_BEGINNING, GridData.VERTICAL_ALIGN_CENTER, true,
                true, 2, 1);
        gd.horizontalIndent = horizontalIndent;
        l.setLayoutData(gd);

        SelectionAdapter selectionAdapter = new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent event) {
                sTracingEnabled = useTracingButton.getSelection();
                samplingIntervalTextField.setEnabled(!sTracingEnabled);
            }
        };
        useTracingButton.addSelectionListener(selectionAdapter);
        useSamplingButton.addSelectionListener(selectionAdapter);

        return c;
    }

    public boolean shouldUseTracing() {
        return sTracingEnabled;
    }

    public int getSamplingIntervalMicros() {
        return sSamplingIntervalUs;
    }
}
