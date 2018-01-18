/*
 * Copyright (C) 2008 The Android Open Source Project
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

import com.android.annotations.concurrency.GuardedBy;
import com.android.ddmlib.AdbCommandRejectedException;
import com.android.ddmlib.Client;
import com.android.ddmlib.ClientData;
import com.android.ddmlib.IDevice;
import com.android.ddmlib.IShellOutputReceiver;
import com.android.ddmlib.Log;
import com.android.ddmlib.NullOutputReceiver;
import com.android.ddmlib.ShellCommandUnresponsiveException;
import com.android.ddmlib.TimeoutException;
import com.android.ddmuilib.SysinfoPanel.BugReportParser.GfxProfileData;
import com.google.common.base.Splitter;
import com.google.common.collect.Lists;

import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.StackLayout;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.layout.RowLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Label;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.experimental.chart.swt.ChartComposite;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Displays system information graphs obtained from a bugreport file or device.
 */
public class SysinfoPanel extends TablePanel {

    // UI components
    private Label mLabel;
    private Button mFetchButton;
    private Combo mDisplayMode;

    private DefaultPieDataset mDataset;
    private DefaultCategoryDataset mBarDataSet;

    private StackLayout mStackLayout;
    private Composite mChartComposite;
    private Composite mPieChartComposite;
    private Composite mStackedBarComposite;

    // Selects the current display: MODE_CPU, etc.
    private int mMode = 0;
    private String mGfxPackageName;

    private static final Object RECEIVER_LOCK = new Object();
    @GuardedBy("RECEIVER_LOCK")
    private ShellOutputReceiver mLastOutputReceiver;

    private static final int MODE_CPU = 0;
    private static final int MODE_MEMINFO = 1;
    private static final int MODE_GFXINFO = 2;

    // argument to dumpsys; section in the bugreport holding the data
    private static final String DUMP_COMMAND[] = {
        "dumpsys cpuinfo",
        "cat /proc/meminfo ; procrank",
        "dumpsys gfxinfo",
    };

    private static final String CAPTIONS[] = {
        "CPU load",
        "Memory usage",
        "Frame Render Time",
    };

    /** Shell property that controls whether graphics profiling is enabled or not. */
    private static final String PROP_GFX_PROFILING = "debug.hwui.profile"; //$NON-NLS-1$

    /**
     * Generates the dataset to display.
     *
     * @param file The bugreport file to process.
     */
    private void generateDataset(File file) {
        if (file == null) {
            return;
        }
        try {
            BufferedReader br = getBugreportReader(file);
            if (mMode == MODE_CPU) {
                readCpuDataset(br);
            } else if (mMode == MODE_MEMINFO) {
                readMeminfoDataset(br);
            } else if (mMode == MODE_GFXINFO) {
                readGfxInfoDataset(br);
            }
            br.close();
        } catch (IOException e) {
            Log.e("DDMS", e);
        }
    }

    /**
     * Sent when a new device is selected. The new device can be accessed with
     * {@link #getCurrentDevice()}
     */
    @Override
    public void deviceSelected() {
        if (getCurrentDevice() != null) {
            mFetchButton.setEnabled(true);
            loadFromDevice();
        } else {
            mFetchButton.setEnabled(false);
        }
    }

    /**
     * Sent when a new client is selected. The new client can be accessed with
     * {@link #getCurrentClient()}.
     */
    @Override
    public void clientSelected() {
    }

    /**
     * Sets the focus to the proper control inside the panel.
     */
    @Override
    public void setFocus() {
        mDisplayMode.setFocus();
    }

    /**
     * Fetches a new bugreport from the device and updates the display.
     * Fetching is asynchronous.  See also addOutput, flush, and isCancelled.
     */
    private void loadFromDevice() {
        clearDataSet();

        if (mMode == MODE_GFXINFO) {
            boolean en = isGfxProfilingEnabled();
            if (!en) {
                if (enableGfxProfiling()) {
                    MessageDialog.openInformation(Display.getCurrent().getActiveShell(),
                            "DDMS",
                            "Graphics profiling was enabled on the device.\n" +
                            "It may be necessary to relaunch your application to see profile information.");
                } else {
                    MessageDialog.openError(Display.getCurrent().getActiveShell(),
                            "DDMS",
                            "Unexpected error enabling graphics profiling on device.\n");
                    return;
                }
            }
        }

        final String command = getDumpsysCommand(mMode);
        if (command == null) {
            return;
        }

        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    String header = null;
                    if (mMode == MODE_MEMINFO) {
                        // Hack to add bugreport-style section header for meminfo
                        header = "------ MEMORY INFO ------\n";
                    }

                    IShellOutputReceiver receiver = initShellOutputBuffer(header);
                    getCurrentDevice().executeShellCommand(command, receiver);
                } catch (IOException e) {
                    Log.e("DDMS", e);
                } catch (TimeoutException e) {
                    Log.e("DDMS", e);
                } catch (AdbCommandRejectedException e) {
                    Log.e("DDMS", e);
                } catch (ShellCommandUnresponsiveException e) {
                    Log.e("DDMS", e);
                }
            }
        }, "Sysinfo Output Collector");
        t.start();
    }

    private boolean isGfxProfilingEnabled() {
        IDevice device = getCurrentDevice();
        if (device == null) {
            return false;
        }

        String prop;
        try {
            prop = device.getPropertySync(PROP_GFX_PROFILING);
            return Boolean.valueOf(prop);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean enableGfxProfiling() {
        IDevice device = getCurrentDevice();
        if (device == null) {
            return false;
        }

        try {
            device.executeShellCommand("setprop " + PROP_GFX_PROFILING + " true",
                    new NullOutputReceiver());
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    private String getDumpsysCommand(int mode) {
        if (mode == MODE_GFXINFO) {
            Client c = getCurrentClient();
            if (c == null) {
                return null;
            }

            ClientData cd = c.getClientData();
            if (cd == null) {
                return null;
            }

            mGfxPackageName = cd.getClientDescription();
            if (mGfxPackageName == null) {
                return null;
            }

            return "dumpsys gfxinfo " + mGfxPackageName;
        } else if (mode < DUMP_COMMAND.length) {
            return DUMP_COMMAND[mode];
        }

        return null;
    }

    /**
     * Initializes temporary output file for executeShellCommand().
     *
     * @throws IOException on file error
     */
    IShellOutputReceiver initShellOutputBuffer(String header) throws IOException {
        File f = File.createTempFile("ddmsfile", ".txt");
        f.deleteOnExit();

        synchronized (RECEIVER_LOCK) {
            if (mLastOutputReceiver != null) {
                mLastOutputReceiver.cancel();
            }

            mLastOutputReceiver = new ShellOutputReceiver(f, header);
        }
        return mLastOutputReceiver;
    }

    /**
     * Create our controls for the UI panel.
     */
    @Override
    protected Control createControl(Composite parent) {
        Composite top = new Composite(parent, SWT.NONE);
        top.setLayout(new GridLayout(1, false));
        top.setLayoutData(new GridData(GridData.FILL_BOTH));

        Composite buttons = new Composite(top, SWT.NONE);
        buttons.setLayout(new RowLayout());

        mDisplayMode = new Combo(buttons, SWT.PUSH);
        for (String mode : CAPTIONS) {
            mDisplayMode.add(mode);
        }
        mDisplayMode.select(mMode);
        mDisplayMode.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                mMode = mDisplayMode.getSelectionIndex();
                if (getCurrentDevice() != null) {
                    loadFromDevice();
                }
            }
        });

        mFetchButton = new Button(buttons, SWT.PUSH);
        mFetchButton.setText("Update from Device");
        mFetchButton.setEnabled(false);
        mFetchButton.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                loadFromDevice();
            }
        });

        mLabel = new Label(top, SWT.NONE);
        mLabel.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));

        mChartComposite = new Composite(top, SWT.NONE);
        mChartComposite.setLayoutData(new GridData(GridData.FILL_BOTH));
        mStackLayout = new StackLayout();
        mChartComposite.setLayout(mStackLayout);

        mPieChartComposite = createPieChartComposite(mChartComposite);
        mStackedBarComposite = createStackedBarComposite(mChartComposite);

        mStackLayout.topControl = mPieChartComposite;

        return top;
    }

    private Composite createStackedBarComposite(Composite chartComposite) {
        mBarDataSet = new DefaultCategoryDataset();
        JFreeChart chart = ChartFactory.createStackedBarChart("Per Frame Rendering Time",
                "Frame #", "Time (ms)", mBarDataSet, PlotOrientation.VERTICAL,
                true /* legend */, true /* tooltips */, false /* urls */);

        ChartComposite c = newChartComposite(chart, chartComposite);
        c.setLayoutData(new GridData(GridData.FILL_BOTH));
        return c;
    }

    private Composite createPieChartComposite(Composite chartComposite) {
        mDataset = new DefaultPieDataset();
        JFreeChart chart = ChartFactory.createPieChart("", mDataset, false
                /* legend */, true/* tooltips */, false /* urls */);

        ChartComposite c = newChartComposite(chart, chartComposite);
        c.setLayoutData(new GridData(GridData.FILL_BOTH));
        return c;
    }

    private ChartComposite newChartComposite(JFreeChart chart, Composite parent) {
        return new ChartComposite(parent,
                SWT.BORDER, chart,
                ChartComposite.DEFAULT_HEIGHT,
                ChartComposite.DEFAULT_HEIGHT,
                ChartComposite.DEFAULT_MINIMUM_DRAW_WIDTH,
                ChartComposite.DEFAULT_MINIMUM_DRAW_HEIGHT,
                3000,
                // max draw width. We don't want it to zoom, so we put a big number
                3000,
                // max draw height. We don't want it to zoom, so we put a big number
                true,  // off-screen buffer
                true,  // properties
                true,  // save
                true,  // print
                false,  // zoom
                true);
    }

    @Override
    public void clientChanged(final Client client, int changeMask) {
        // Don't care
    }

    /**
     * Helper to open a bugreport and skip to the specified section.
     *
     * @param file File to open
     * @return Reader to bugreport file
     * @throws java.io.IOException on file error
     */
    private BufferedReader getBugreportReader(File file) throws
            IOException {
        return new BufferedReader(new FileReader(file));
    }

    /**
     * Parse the time string generated by BatteryStats.
     * A typical new-format string is "11d 13h 45m 39s 999ms".
     * A typical old-format string is "12.3 sec".
     * @return time in ms
     */
    private static long parseTimeMs(String s) {
        long total = 0;
        // Matches a single component e.g. "12.3 sec" or "45ms"
        Pattern p = Pattern.compile("([\\d\\.]+)\\s*([a-z]+)");
        Matcher m = p.matcher(s);
        while (m.find()) {
            String label = m.group(2);
            if ("sec".equals(label)) {
                // Backwards compatibility with old time format
                total += (long) (Double.parseDouble(m.group(1)) * 1000);
                continue;
            }
            long value = Integer.parseInt(m.group(1));
            if ("d".equals(label)) {
                total += value * 24 * 60 * 60 * 1000;
            } else if ("h".equals(label)) {
                total += value * 60 * 60 * 1000;
            } else if ("m".equals(label)) {
                total += value * 60 * 1000;
            } else if ("s".equals(label)) {
                total += value * 1000;
            } else if ("ms".equals(label)) {
                total += value;
            }
        }
        return total;
    }

    public static final class BugReportParser {
        public static final class DataValue {
            final String name;
            final double value;

            public DataValue(String n, double v) {
                name = n;
                value = v;
            }
        };

        /** Components of the time it takes to draw a single frame. */
        public static final class GfxProfileData {
            /** draw time (time spent building display lists) in ms */
            final double draw;

            /** process time (time spent by Android's 2D renderer to execute display lists) (ms) */
            final double process;

            /** execute time (time spent to send frame to the compositor) in ms */
            final double execute;

            public GfxProfileData(double draw, double process, double execute) {
                this.draw = draw;
                this.process = process;
                this.execute = execute;
            }
        }

        public static List<GfxProfileData> parseGfxInfo(BufferedReader br) throws IOException {
            Pattern headerPattern = Pattern.compile("\\s+Draw\\s+Process\\s+Execute");

            String line = null;
            while ((line = br.readLine()) != null) {
                Matcher m = headerPattern.matcher(line);
                if (m.find()) {
                    break;
                }
            }

            if (line == null) {
                return Collections.emptyList();
            }

            // parse something like: "  0.85    1.10    0.61\n", 3 doubles basically
            Pattern dataPattern =
                    Pattern.compile("(\\d*\\.\\d+)\\s+(\\d*\\.\\d+)\\s+(\\d*\\.\\d+)");

            List<GfxProfileData> data = new ArrayList<BugReportParser.GfxProfileData>(128);
            while ((line = br.readLine()) != null) {
                Matcher m = dataPattern.matcher(line);
                if (!m.find()) {
                    break;
                }

                double draw = safeParseDouble(m.group(1));
                double process = safeParseDouble(m.group(2));
                double execute = safeParseDouble(m.group(3));

                data.add(new GfxProfileData(draw, process, execute));
            }

            return data;
        }

        /**
         * Processes wakelock information from bugreport. Updates mDataset with the
         * new data.
         *
         * @param br Reader providing the content
         * @throws IOException if error reading file
         */
        public static List<DataValue> readWakelockDataset(BufferedReader br) throws IOException {
            List<DataValue> results = new ArrayList<DataValue>();

            Pattern lockPattern = Pattern.compile("Wake lock (\\S+): (.+) partial");
            Pattern totalPattern = Pattern.compile("Total: (.+) uptime");
            double total = 0;
            boolean inCurrent = false;

            while (true) {
                String line = br.readLine();
                if (line == null || line.startsWith("DUMP OF SERVICE")) {
                    // Done, or moved on to the next service
                    break;
                }
                if (line.startsWith("Current Battery Usage Statistics")) {
                    inCurrent = true;
                } else if (inCurrent) {
                    Matcher m = lockPattern.matcher(line);
                    if (m.find()) {
                        double value = parseTimeMs(m.group(2)) / 1000.;
                        results.add(new DataValue(m.group(1), value));
                        total -= value;
                    } else {
                        m = totalPattern.matcher(line);
                        if (m.find()) {
                            total += parseTimeMs(m.group(1)) / 1000.;
                        }
                    }
                }
            }
            if (total > 0) {
                results.add(new DataValue("Unlocked", total));
            }

            return results;
        }

        /**
         * Processes alarm information from bugreport. Updates mDataset with the new
         * data.
         *
         * @param br Reader providing the content
         * @throws IOException if error reading file
         */
        public static List<DataValue> readAlarmDataset(BufferedReader br) throws IOException {
            List<DataValue> results = new ArrayList<DataValue>();
            Pattern pattern = Pattern.compile("(\\d+) alarms: Intent .*\\.([^. ]+) flags");

            while (true) {
                String line = br.readLine();
                if (line == null || line.startsWith("DUMP OF SERVICE")) {
                    // Done, or moved on to the next service
                    break;
                }
                Matcher m = pattern.matcher(line);
                if (m.find()) {
                    long count = Long.parseLong(m.group(1));
                    String name = m.group(2);
                    results.add(new DataValue(name, count));
                }
            }

            return results;
        }

        /**
         * Processes cpu load information from bugreport. Updates mDataset with the
         * new data.
         *
         * @param br Reader providing the content
         * @throws IOException if error reading file
         */
        public static List<DataValue> readCpuDataset(BufferedReader br) throws IOException {
            List<DataValue> results = new ArrayList<DataValue>();
            Pattern pattern1 = Pattern.compile("(\\S+): (\\S+)% = (.+)% user . (.+)% kernel");
            Pattern pattern2 = Pattern.compile("(\\S+)% (\\S+): (.+)% user . (.+)% kernel");

            while (true) {
                String line = br.readLine();
                if (line == null) {
                    break;
                }
                line = line.trim();

                if (line.startsWith("Load:")) {
                    continue;
                }

                String name = "";
                double user = 0, kernel = 0, both = 0;
                boolean found = false;

                // try pattern1
                Matcher m = pattern1.matcher(line);
                if (m.find()) {
                    found = true;
                    name = m.group(1);
                    both = safeParseLong(m.group(2));
                    user = safeParseLong(m.group(3));
                    kernel = safeParseLong(m.group(4));
                }

                // try pattern2
                m = pattern2.matcher(line);
                if (m.find()) {
                    found = true;
                    name = m.group(2);
                    both = safeParseDouble(m.group(1));
                    user = safeParseDouble(m.group(3));
                    kernel = safeParseDouble(m.group(4));
                }

                if (!found) {
                    continue;
                }

                if ("TOTAL".equals(name)) {
                    if (both < 100) {
                        results.add(new DataValue("Idle", (100 - both)));
                    }
                } else {
                    // Try to make graphs more useful even with rounding;
                    // log often has 0% user + 0% kernel = 1% total
                    // We arbitrarily give extra to kernel
                    if (user > 0) {
                        results.add(new DataValue(name + " (user)", user));
                    }
                    if (kernel > 0) {
                        results.add(new DataValue(name + " (kernel)" , both - user));
                    }
                    if (user == 0 && kernel == 0 && both > 0) {
                        results.add(new DataValue(name, both));
                    }
                }

            }

            return results;
        }

        private static long safeParseLong(String s) {
            try {
                return Long.parseLong(s);
            } catch (NumberFormatException e) {
                return 0;
            }
        }

        private static double safeParseDouble(String s) {
            try {
                return Double.parseDouble(s);
            } catch (NumberFormatException e) {
                return 0;
            }
        }

        /**
         * Processes meminfo information from bugreport. Updates mDataset with the
         * new data.
         *
         * @param br Reader providing the content
         * @throws IOException if error reading file
         */
        public static List<DataValue> readMeminfoDataset(BufferedReader br) throws IOException {
            List<DataValue> results = new ArrayList<DataValue>();
            Pattern valuePattern = Pattern.compile("(\\d+) kB");
            long total = 0;
            long other = 0;

            // Scan meminfo
            String line = null;
            while ((line = br.readLine()) != null) {
                if (line.contains("----")) {
                    continue;
                }

                Matcher m = valuePattern.matcher(line);
                if (m.find()) {
                    long kb = Long.parseLong(m.group(1));
                    if (line.startsWith("MemTotal")) {
                        total = kb;
                    } else if (line.startsWith("MemFree")) {
                        results.add(new DataValue("Free", kb));
                        total -= kb;
                    } else if (line.startsWith("Slab")) {
                        results.add(new DataValue("Slab", kb));
                        total -= kb;
                    } else if (line.startsWith("PageTables")) {
                        results.add(new DataValue("PageTables", kb));
                        total -= kb;
                    } else if (line.startsWith("Buffers") && kb > 0) {
                        results.add(new DataValue("Buffers", kb));
                        total -= kb;
                    } else if (line.startsWith("Inactive")) {
                        results.add(new DataValue("Inactive", kb));
                        total -= kb;
                    } else if (line.startsWith("MemFree")) {
                        results.add(new DataValue("Free", kb));
                        total -= kb;
                    }
                } else {
                    break;
                }
            }

            List<DataValue> procRankResults = readProcRankDataset(br, line);
            for (DataValue procRank : procRankResults) {
                if (procRank.value > 2000) { // only show processes using > 2000K in memory
                    results.add(procRank);
                } else {
                    other += procRank.value;
                }

                total -= procRank.value;
            }

            if (other > 0) {
                results.add(new DataValue("Other", other));
            }

            // The Pss calculation is not necessarily accurate as accounting memory to
            // a process is not accurate. So only if there really is unaccounted for memory do we
            // add it to the pie.
            if (total > 0) {
                results.add(new DataValue("Unknown", total));
            }

            return results;
        }

        static List<DataValue> readProcRankDataset(BufferedReader br, String header)
                throws IOException {
            List<DataValue> results = new ArrayList<DataValue>();

            if (header == null || !header.contains("PID")) {
                return results;
            }

            Splitter PROCRANK_SPLITTER = Splitter.on(' ').omitEmptyStrings().trimResults();
            List<String> fields = Lists.newArrayList(PROCRANK_SPLITTER.split(header));
            int pssIndex = fields.indexOf("Pss");
            int cmdIndex = fields.indexOf("cmdline");

            if (pssIndex == -1 || cmdIndex == -1) {
                return results;
            }

            String line;
            while ((line = br.readLine()) != null) {
                // Extract pss field from procrank output
                fields = Lists.newArrayList(PROCRANK_SPLITTER.split(line));

                if (fields.size() < cmdIndex) {
                    break;
                }

                String cmdline = fields.get(cmdIndex).replace("/system/bin/", "");
                String pssInK = fields.get(pssIndex);
                if (pssInK.endsWith("K")) {
                    pssInK = pssInK.substring(0, pssInK.length() - 1);
                }
                long pss = safeParseLong(pssInK);
                results.add(new DataValue(cmdline, pss));
            }

            return results;
        }

        /**
         * Processes sync information from bugreport. Updates mDataset with the new
         * data.
         *
         * @param br Reader providing the content
         * @throws IOException if error reading file
         */
        public static List<DataValue> readSyncDataset(BufferedReader br) throws IOException {
            List<DataValue> results = new ArrayList<DataValue>();

            while (true) {
                String line = br.readLine();
                if (line == null || line.startsWith("DUMP OF SERVICE")) {
                    // Done, or moved on to the next service
                    break;
                }
                if (line.startsWith(" |") && line.length() > 70) {
                    String authority = line.substring(3, 18).trim();
                    String duration = line.substring(61, 70).trim();
                    // Duration is MM:SS or HH:MM:SS (DateUtils.formatElapsedTime)
                    String durParts[] = duration.split(":");
                    if (durParts.length == 2) {
                        long dur = Long.parseLong(durParts[0]) * 60 + Long
                                .parseLong(durParts[1]);
                        results.add(new DataValue(authority, dur));
                    } else if (duration.length() == 3) {
                        long dur = Long.parseLong(durParts[0]) * 3600
                                + Long.parseLong(durParts[1]) * 60 + Long
                                .parseLong(durParts[2]);
                        results.add(new DataValue(authority, dur));
                    }
                }
            }

            return results;
        }
    }

    private void readCpuDataset(BufferedReader br) throws IOException {
        updatePieDataSet(BugReportParser.readCpuDataset(br), "");
    }

    private void readMeminfoDataset(BufferedReader br) throws IOException {
        updatePieDataSet(BugReportParser.readMeminfoDataset(br), "PSS in kB");
    }

    private void readGfxInfoDataset(BufferedReader br) throws IOException {
        updateBarChartDataSet(BugReportParser.parseGfxInfo(br),
                mGfxPackageName == null ? "" : mGfxPackageName);
    }

    private void clearDataSet() {
        mLabel.setText("");
        mDataset.clear();
        mBarDataSet.clear();
    }

    private void updatePieDataSet(final List<BugReportParser.DataValue> data, final String label) {
        Display.getDefault().syncExec(new Runnable() {
            @Override
            public void run() {
                mLabel.setText(label);
                mStackLayout.topControl = mPieChartComposite;
                mChartComposite.layout();

                for (BugReportParser.DataValue d : data) {
                    mDataset.setValue(d.name, d.value);
                }
            }
        });
    }

    private void updateBarChartDataSet(final List<GfxProfileData> gfxProfileData,
            final String label) {
        Display.getDefault().syncExec(new Runnable() {
            @Override
            public void run() {
                mLabel.setText(label);
                mStackLayout.topControl = mStackedBarComposite;
                mChartComposite.layout();

                for (int i = 0; i < gfxProfileData.size(); i++) {
                    GfxProfileData d = gfxProfileData.get(i);
                    String frameNumber = Integer.toString(i);

                    mBarDataSet.addValue(d.draw, "Draw", frameNumber);
                    mBarDataSet.addValue(d.process, "Process", frameNumber);
                    mBarDataSet.addValue(d.execute, "Execute", frameNumber);
                }
            }
        });
    }

    private class ShellOutputReceiver implements IShellOutputReceiver {
        private final OutputStream mStream;
        private final File mFile;
        private AtomicBoolean mCancelled = new AtomicBoolean();

        public ShellOutputReceiver(File f, String header) {
            mFile = f;
            try {
                mStream = new FileOutputStream(f);
            } catch (FileNotFoundException e) {
                throw new IllegalArgumentException(e);
            }

            if (header != null) {
                byte[] data = header.getBytes();
                addOutput(data, 0, data.length);
            }
        }

        @Override
        public void addOutput(byte[] data, int offset, int length) {
            try {
                mStream.write(data, offset, length);
            } catch (IOException e) {
                Log.e("DDMS", e);
            }
        }

        @Override
        public void flush() {
            try {
                mStream.close();
            } catch (IOException e) {
                Log.e("DDMS", e);
            }

            if (!isCancelled()) {
                generateDataset(mFile);
            }
        }

        @Override
        public boolean isCancelled() {
            return mCancelled.get();
        }

        public void cancel() {
            mCancelled.set(true);
        }

        public File getDataFile() {
            return mFile;
        }
    }
}
