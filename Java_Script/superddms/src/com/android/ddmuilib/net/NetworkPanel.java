/*
 * Copyright (C) 2012 The Android Open Source Project
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

package com.android.ddmuilib.net;

import com.android.ddmlib.AdbCommandRejectedException;
import com.android.ddmlib.Client;
import com.android.ddmlib.IDevice;
import com.android.ddmlib.MultiLineReceiver;
import com.android.ddmlib.ShellCommandUnresponsiveException;
import com.android.ddmlib.TimeoutException;
import com.android.ddmuilib.DdmUiPreferences;
import com.android.ddmuilib.TableHelper;
import com.android.ddmuilib.TablePanel;

import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Status;
import org.eclipse.jface.dialogs.ErrorDialog;
import org.eclipse.jface.preference.IPreferenceStore;
import org.eclipse.jface.viewers.ILabelProviderListener;
import org.eclipse.jface.viewers.IStructuredContentProvider;
import org.eclipse.jface.viewers.ITableLabelProvider;
import org.eclipse.jface.viewers.TableViewer;
import org.eclipse.jface.viewers.Viewer;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.graphics.GC;
import org.eclipse.swt.graphics.Image;
import org.eclipse.swt.layout.FormAttachment;
import org.eclipse.swt.layout.FormData;
import org.eclipse.swt.layout.FormLayout;
import org.eclipse.swt.layout.RowLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Table;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.AxisLocation;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.plot.DatasetRenderingOrder;
import org.jfree.chart.plot.ValueMarker;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.StackedXYAreaRenderer2;
import org.jfree.chart.renderer.xy.XYAreaRenderer;
import org.jfree.data.DefaultKeyedValues2D;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimePeriod;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;
import org.jfree.data.xy.AbstractIntervalXYDataset;
import org.jfree.data.xy.TableXYDataset;
import org.jfree.experimental.chart.swt.ChartComposite;
import org.jfree.ui.RectangleAnchor;
import org.jfree.ui.TextAnchor;

import java.io.IOException;
import java.text.DecimalFormat;
import java.text.FieldPosition;
import java.text.NumberFormat;
import java.text.ParsePosition;
import java.util.ArrayList;
import java.util.Date;
import java.util.Formatter;
import java.util.Iterator;

/**
 * Displays live network statistics for currently selected {@link Client}.
 */
public class NetworkPanel extends TablePanel {

    // TODO: enable view of packets and bytes/packet
    // TODO: add sash to resize chart and table
    // TODO: let user edit tags to be meaningful

    /** Amount of historical data to display. */
    private static final long HISTORY_MILLIS = 30 * 1000;

    private final static String PREFS_NETWORK_COL_TITLE = "networkPanel.title";
    private final static String PREFS_NETWORK_COL_RX_BYTES = "networkPanel.rxBytes";
    private final static String PREFS_NETWORK_COL_RX_PACKETS = "networkPanel.rxPackets";
    private final static String PREFS_NETWORK_COL_TX_BYTES = "networkPanel.txBytes";
    private final static String PREFS_NETWORK_COL_TX_PACKETS = "networkPanel.txPackets";

    /** Path to network statistics on remote device. */
    private static final String PROC_XT_QTAGUID = "/proc/net/xt_qtaguid/stats";

    private static final java.awt.Color TOTAL_COLOR = java.awt.Color.GRAY;

    /** Colors used for tag series data. */
    private static final java.awt.Color[] SERIES_COLORS = new java.awt.Color[] {
        java.awt.Color.decode("0x2bc4c1"), // teal
        java.awt.Color.decode("0xD50F25"), // red
        java.awt.Color.decode("0x3369E8"), // blue
        java.awt.Color.decode("0xEEB211"), // orange
        java.awt.Color.decode("0x00bd2e"), // green
        java.awt.Color.decode("0xae26ae"), // purple
    };

    private Display mDisplay;

    private Composite mPanel;

    /** Header panel with configuration options. */
    private Composite mHeader;

    private Label mSpeedLabel;
    private Combo mSpeedCombo;

    /** Current sleep between each sample, from {@link #mSpeedCombo}. */
    private long mSpeedMillis;

    private Button mRunningButton;
    private Button mResetButton;

    /** Chart of recent network activity. */
    private JFreeChart mChart;
    private ChartComposite mChartComposite;

    private ValueAxis mDomainAxis;

    /** Data for total traffic (tag 0x0).  */
    private TimeSeriesCollection mTotalCollection;
    private TimeSeries mRxTotalSeries;
    private TimeSeries mTxTotalSeries;

    /** Data for detailed tagged traffic. */
    private LiveTimeTableXYDataset mRxDetailDataset;
    private LiveTimeTableXYDataset mTxDetailDataset;

    private XYAreaRenderer mTotalRenderer;
    private StackedXYAreaRenderer2 mRenderer;

    /** Table showing summary of network activity. */
    private Table mTable;
    private TableViewer mTableViewer;

    /** UID of currently selected {@link Client}. */
    private int mActiveUid = -1;

    /** List of traffic flows being actively tracked. */
    private ArrayList<TrackedItem> mTrackedItems = new ArrayList<TrackedItem>();

    private SampleThread mSampleThread;

    private class SampleThread extends Thread {
        private volatile boolean mFinish;

        public void finish() {
            mFinish = true;
            interrupt();
        }

        @Override
        public void run() {
            while (!mFinish && !mDisplay.isDisposed()) {
                performSample();

                try {
                    Thread.sleep(mSpeedMillis);
                } catch (InterruptedException e) {
                    // ignored
                }
            }
        }
    }

    /** Last snapshot taken by {@link #performSample()}. */
    private NetworkSnapshot mLastSnapshot;

    @Override
    protected Control createControl(Composite parent) {
        mDisplay = parent.getDisplay();

        mPanel = new Composite(parent, SWT.NONE);

        final FormLayout formLayout = new FormLayout();
        mPanel.setLayout(formLayout);

        createHeader();
        createChart();
        createTable();

        return mPanel;
    }

    /**
     * Create header panel with configuration options.
     */
    private void createHeader() {

        mHeader = new Composite(mPanel, SWT.NONE);
        final RowLayout layout = new RowLayout();
        layout.center = true;
        mHeader.setLayout(layout);

        mSpeedLabel = new Label(mHeader, SWT.NONE);
        mSpeedLabel.setText("Speed:");
        mSpeedCombo = new Combo(mHeader, SWT.PUSH);
        mSpeedCombo.add("Fast (100ms)");
        mSpeedCombo.add("Medium (250ms)");
        mSpeedCombo.add("Slow (500ms)");
        mSpeedCombo.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                updateSpeed();
            }
        });

        mSpeedCombo.select(1);
        updateSpeed();

        mRunningButton = new Button(mHeader, SWT.PUSH);
        mRunningButton.setText("Start");
        mRunningButton.setEnabled(false);
        mRunningButton.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                final boolean alreadyRunning = mSampleThread != null;
                updateRunning(!alreadyRunning);
            }
        });

        mResetButton = new Button(mHeader, SWT.PUSH);
        mResetButton.setText("Reset");
        mResetButton.addSelectionListener(new SelectionAdapter() {
            @Override
            public void widgetSelected(SelectionEvent e) {
                clearTrackedItems();
            }
        });

        final FormData data = new FormData();
        data.top = new FormAttachment(0);
        data.left = new FormAttachment(0);
        data.right = new FormAttachment(100);
        mHeader.setLayoutData(data);
    }

    /**
     * Create chart of recent network activity.
     */
    private void createChart() {

        mChart = ChartFactory.createTimeSeriesChart(null, null, null, null, false, false, false);

        // create backing datasets and series
        mRxTotalSeries = new TimeSeries("RX total");
        mTxTotalSeries = new TimeSeries("TX total");

        mRxTotalSeries.setMaximumItemAge(HISTORY_MILLIS);
        mTxTotalSeries.setMaximumItemAge(HISTORY_MILLIS);

        mTotalCollection = new TimeSeriesCollection();
        mTotalCollection.addSeries(mRxTotalSeries);
        mTotalCollection.addSeries(mTxTotalSeries);

        mRxDetailDataset = new LiveTimeTableXYDataset();
        mTxDetailDataset = new LiveTimeTableXYDataset();

        mTotalRenderer = new XYAreaRenderer(XYAreaRenderer.AREA);
        mRenderer = new StackedXYAreaRenderer2();

        final XYPlot xyPlot = mChart.getXYPlot();

        xyPlot.setDatasetRenderingOrder(DatasetRenderingOrder.FORWARD);

        xyPlot.setDataset(0, mTotalCollection);
        xyPlot.setDataset(1, mRxDetailDataset);
        xyPlot.setDataset(2, mTxDetailDataset);
        xyPlot.setRenderer(0, mTotalRenderer);
        xyPlot.setRenderer(1, mRenderer);
        xyPlot.setRenderer(2, mRenderer);

        // we control domain axis manually when taking samples
        mDomainAxis = xyPlot.getDomainAxis();
        mDomainAxis.setAutoRange(false);

        final NumberAxis axis = new NumberAxis();
        axis.setNumberFormatOverride(new BytesFormat(true));
        axis.setAutoRangeMinimumSize(50);
        xyPlot.setRangeAxis(axis);
        xyPlot.setRangeAxisLocation(AxisLocation.BOTTOM_OR_RIGHT);

        // draw thick line to separate RX versus TX traffic
        xyPlot.addRangeMarker(
                new ValueMarker(0, java.awt.Color.BLACK, new java.awt.BasicStroke(2)));

        // label to indicate that positive axis is RX traffic
        final ValueMarker rxMarker = new ValueMarker(0);
        rxMarker.setStroke(new java.awt.BasicStroke(0));
        rxMarker.setLabel("RX");
        rxMarker.setLabelFont(rxMarker.getLabelFont().deriveFont(30f));
        rxMarker.setLabelPaint(java.awt.Color.LIGHT_GRAY);
        rxMarker.setLabelAnchor(RectangleAnchor.TOP_RIGHT);
        rxMarker.setLabelTextAnchor(TextAnchor.BOTTOM_RIGHT);
        xyPlot.addRangeMarker(rxMarker);

        // label to indicate that negative axis is TX traffic
        final ValueMarker txMarker = new ValueMarker(0);
        txMarker.setStroke(new java.awt.BasicStroke(0));
        txMarker.setLabel("TX");
        txMarker.setLabelFont(txMarker.getLabelFont().deriveFont(30f));
        txMarker.setLabelPaint(java.awt.Color.LIGHT_GRAY);
        txMarker.setLabelAnchor(RectangleAnchor.BOTTOM_RIGHT);
        txMarker.setLabelTextAnchor(TextAnchor.TOP_RIGHT);
        xyPlot.addRangeMarker(txMarker);

        mChartComposite = new ChartComposite(mPanel, SWT.BORDER, mChart,
                ChartComposite.DEFAULT_WIDTH, ChartComposite.DEFAULT_HEIGHT,
                ChartComposite.DEFAULT_MINIMUM_DRAW_WIDTH,
                ChartComposite.DEFAULT_MINIMUM_DRAW_HEIGHT, 4096, 4096, true, true, true, true,
                false, true);

        final FormData data = new FormData();
        data.top = new FormAttachment(mHeader);
        data.left = new FormAttachment(0);
        data.bottom = new FormAttachment(70);
        data.right = new FormAttachment(100);
        mChartComposite.setLayoutData(data);
    }

    /**
     * Create table showing summary of network activity.
     */
    private void createTable() {
        mTable = new Table(mPanel, SWT.BORDER | SWT.MULTI | SWT.FULL_SELECTION);

        final FormData data = new FormData();
        data.top = new FormAttachment(mChartComposite);
        data.left = new FormAttachment(mChartComposite, 0, SWT.CENTER);
        data.bottom = new FormAttachment(100);
        mTable.setLayoutData(data);

        mTable.setHeaderVisible(true);
        mTable.setLinesVisible(true);

        final IPreferenceStore store = DdmUiPreferences.getStore();

        TableHelper.createTableColumn(mTable, "", SWT.CENTER, buildSampleText(2), null, null);
        TableHelper.createTableColumn(
                mTable, "Tag", SWT.LEFT, buildSampleText(32), PREFS_NETWORK_COL_TITLE, store);
        TableHelper.createTableColumn(mTable, "RX bytes", SWT.RIGHT, buildSampleText(12),
                PREFS_NETWORK_COL_RX_BYTES, store);
        TableHelper.createTableColumn(mTable, "RX packets", SWT.RIGHT, buildSampleText(12),
                PREFS_NETWORK_COL_RX_PACKETS, store);
        TableHelper.createTableColumn(mTable, "TX bytes", SWT.RIGHT, buildSampleText(12),
                PREFS_NETWORK_COL_TX_BYTES, store);
        TableHelper.createTableColumn(mTable, "TX packets", SWT.RIGHT, buildSampleText(12),
                PREFS_NETWORK_COL_TX_PACKETS, store);

        mTableViewer = new TableViewer(mTable);
        mTableViewer.setContentProvider(new ContentProvider());
        mTableViewer.setLabelProvider(new LabelProvider());
    }

    /**
     * Update {@link #mSpeedMillis} to match {@link #mSpeedCombo} selection.
     */
    private void updateSpeed() {
        switch (mSpeedCombo.getSelectionIndex()) {
            case 0:
                mSpeedMillis = 100;
                break;
            case 1:
                mSpeedMillis = 250;
                break;
            case 2:
                mSpeedMillis = 500;
                break;
        }
    }

    /**
     * Update if {@link SampleThread} should be actively running. Will create
     * new thread or finish existing thread to match requested state.
     */
    private void updateRunning(boolean shouldRun) {
        final boolean alreadyRunning = mSampleThread != null;
        if (alreadyRunning && !shouldRun) {
            mSampleThread.finish();
            mSampleThread = null;

            mRunningButton.setText("Start");
            mHeader.pack();
        } else if (!alreadyRunning && shouldRun) {
            mSampleThread = new SampleThread();
            mSampleThread.start();

            mRunningButton.setText("Stop");
            mHeader.pack();
        }
    }

    @Override
    public void setFocus() {
        mPanel.setFocus();
    }

    private static java.awt.Color nextSeriesColor(int index) {
        return SERIES_COLORS[index % SERIES_COLORS.length];
    }

    /**
     * Find a {@link TrackedItem} that matches the requested UID and tag, or
     * create one if none exists.
     */
    public TrackedItem findOrCreateTrackedItem(int uid, int tag) {
        // try searching for existing item
        for (TrackedItem item : mTrackedItems) {
            if (item.uid == uid && item.tag == tag) {
                return item;
            }
        }

        // nothing found; create new item
        final TrackedItem item = new TrackedItem(uid, tag);
        if (item.isTotal()) {
            item.color = TOTAL_COLOR;
            item.label = "Total";
        } else {
            final int size = mTrackedItems.size();
            item.color = nextSeriesColor(size);
            Formatter formatter = new Formatter();
            item.label = "0x" + formatter.format("%08x", tag);
            formatter.close();
        }

        // create color chip to display as legend in table
        item.colorImage = new Image(mDisplay, 20, 20);
        final GC gc = new GC(item.colorImage);
        gc.setBackground(new org.eclipse.swt.graphics.Color(mDisplay, item.color
                .getRed(), item.color.getGreen(), item.color.getBlue()));
        gc.fillRectangle(item.colorImage.getBounds());
        gc.dispose();

        mTrackedItems.add(item);
        return item;
    }

    /**
     * Clear all {@link TrackedItem} and chart history.
     */
    public void clearTrackedItems() {
        mRxTotalSeries.clear();
        mTxTotalSeries.clear();

        mRxDetailDataset.clear();
        mTxDetailDataset.clear();

        mTrackedItems.clear();
        mTableViewer.setInput(mTrackedItems);
    }

    /**
     * Update the {@link #mRenderer} colors to match {@link TrackedItem#color}.
     */
    private void updateSeriesPaint() {
        for (TrackedItem item : mTrackedItems) {
            final int seriesIndex = mRxDetailDataset.getColumnIndex(item.label);
            if (seriesIndex >= 0) {
                mRenderer.setSeriesPaint(seriesIndex, item.color);
                mRenderer.setSeriesFillPaint(seriesIndex, item.color);
            }
        }

        // series data is always the same color
        final int count = mTotalCollection.getSeriesCount();
        for (int i = 0; i < count; i++) {
            mTotalRenderer.setSeriesPaint(i, TOTAL_COLOR);
            mTotalRenderer.setSeriesFillPaint(i, TOTAL_COLOR);
        }
    }

    /**
     * Traffic flow being actively tracked, uniquely defined by UID and tag. Can
     * record {@link NetworkSnapshot} deltas into {@link TimeSeries} for
     * charting, and into summary statistics for {@link Table} display.
     */
    private class TrackedItem {
        public final int uid;
        public final int tag;

        public java.awt.Color color;
        public Image colorImage;

        public String label;
        public long rxBytes;
        public long rxPackets;
        public long txBytes;
        public long txPackets;

        public TrackedItem(int uid, int tag) {
            this.uid = uid;
            this.tag = tag;
        }

        public boolean isTotal() {
            return tag == 0x0;
        }

        /**
         * Record the given {@link NetworkSnapshot} delta, updating
         * {@link TimeSeries} and summary statistics.
         *
         * @param time Timestamp when delta was observed.
         * @param deltaMillis Time duration covered by delta, in milliseconds.
         */
        public void recordDelta(Millisecond time, long deltaMillis, NetworkSnapshot.Entry delta) {
            final long rxBytesPerSecond = (delta.rxBytes * 1000) / deltaMillis;
            final long txBytesPerSecond = (delta.txBytes * 1000) / deltaMillis;

            // record values under correct series
            if (isTotal()) {
                mRxTotalSeries.addOrUpdate(time, rxBytesPerSecond);
                mTxTotalSeries.addOrUpdate(time, -txBytesPerSecond);
            } else {
                mRxDetailDataset.addValue(rxBytesPerSecond, time, label);
                mTxDetailDataset.addValue(-txBytesPerSecond, time, label);
            }

            rxBytes += delta.rxBytes;
            rxPackets += delta.rxPackets;
            txBytes += delta.txBytes;
            txPackets += delta.txPackets;
        }
    }

    @Override
    public void deviceSelected() {
        // treat as client selection to update enabled states
        clientSelected();
    }

    @Override
    public void clientSelected() {
        mActiveUid = -1;

        final Client client = getCurrentClient();
        if (client != null) {
            final int pid = client.getClientData().getPid();
            try {
                // map PID to UID from device
                final UidParser uidParser = new UidParser();
                getCurrentDevice().executeShellCommand("cat /proc/" + pid + "/status", uidParser);
                mActiveUid = uidParser.uid;
            } catch (TimeoutException e) {
                e.printStackTrace();
            } catch (AdbCommandRejectedException e) {
                e.printStackTrace();
            } catch (ShellCommandUnresponsiveException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        clearTrackedItems();
        updateRunning(false);

        final boolean validUid = mActiveUid != -1;
        mRunningButton.setEnabled(validUid);
    }

    @Override
    public void clientChanged(Client client, int changeMask) {
        // ignored
    }

    /**
     * Take a snapshot from {@link #getCurrentDevice()}, recording any delta
     * network traffic to {@link TrackedItem}.
     */
    public void performSample() {
        final IDevice device = getCurrentDevice();
        if (device == null) return;

        try {
            final NetworkSnapshotParser parser = new NetworkSnapshotParser();
            device.executeShellCommand("cat " + PROC_XT_QTAGUID, parser);

            if (parser.isError()) {
                mDisplay.asyncExec(new Runnable() {
                    @Override
                    public void run() {
                        updateRunning(false);

                        final String title = "Problem reading stats";
                        final String message = "Problem reading xt_qtaguid network "
                                + "statistics from selected device.";
                        Status status = new Status(IStatus.ERROR, "NetworkPanel", 0, message, null);
                        ErrorDialog.openError(mPanel.getShell(), title, title, status);
                    }
                });

                return;
            }

            final NetworkSnapshot snapshot = parser.getParsedSnapshot();

            // use first snapshot as baseline
            if (mLastSnapshot == null) {
                mLastSnapshot = snapshot;
                return;
            }

            final NetworkSnapshot delta = NetworkSnapshot.subtract(snapshot, mLastSnapshot);
            mLastSnapshot = snapshot;

            // perform delta updates over on UI thread
            if (!mDisplay.isDisposed()) {
                mDisplay.syncExec(new UpdateDeltaRunnable(delta, snapshot.timestamp));
            }

        } catch (TimeoutException e) {
            e.printStackTrace();
        } catch (AdbCommandRejectedException e) {
            e.printStackTrace();
        } catch (ShellCommandUnresponsiveException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Task that updates UI with given {@link NetworkSnapshot} delta.
     */
    private class UpdateDeltaRunnable implements Runnable {
        private final NetworkSnapshot mDelta;
        private final long mEndTime;

        public UpdateDeltaRunnable(NetworkSnapshot delta, long endTime) {
            mDelta = delta;
            mEndTime = endTime;
        }

        @Override
        public void run() {
            if (mDisplay.isDisposed()) return;

            final Millisecond time = new Millisecond(new Date(mEndTime));
            for (NetworkSnapshot.Entry entry : mDelta) {
                if (mActiveUid != entry.uid) continue;

                final TrackedItem item = findOrCreateTrackedItem(entry.uid, entry.tag);
                item.recordDelta(time, mDelta.timestamp, entry);
            }

            // remove any historical detail data
            final long beforeMillis = mEndTime - HISTORY_MILLIS;
            mRxDetailDataset.removeBefore(beforeMillis);
            mTxDetailDataset.removeBefore(beforeMillis);

            // trigger refresh from bulk changes above
            mRxDetailDataset.fireDatasetChanged();
            mTxDetailDataset.fireDatasetChanged();

            // update axis to show latest 30 second time period
            mDomainAxis.setRange(mEndTime - HISTORY_MILLIS, mEndTime);

            updateSeriesPaint();

            // kick table viewer to update
            mTableViewer.setInput(mTrackedItems);
        }
    }

    /**
     * Parser that extracts UID from remote {@code /proc/pid/status} file.
     */
    private static class UidParser extends MultiLineReceiver {
        public int uid = -1;

        @Override
        public boolean isCancelled() {
            return false;
        }

        @Override
        public void processNewLines(String[] lines) {
            for (String line : lines) {
                if (line.startsWith("Uid:")) {
                    // we care about the "real" UID
                    final String[] cols = line.split("\t");
                    uid = Integer.parseInt(cols[1]);
                }
            }
        }
    }

    /**
     * Parser that populates {@link NetworkSnapshot} based on contents of remote
     * {@link NetworkPanel#PROC_XT_QTAGUID} file.
     */
    private static class NetworkSnapshotParser extends MultiLineReceiver {
        private NetworkSnapshot mSnapshot;

        public NetworkSnapshotParser() {
            mSnapshot = new NetworkSnapshot(System.currentTimeMillis());
        }

        public boolean isError() {
            return mSnapshot == null;
        }

        public NetworkSnapshot getParsedSnapshot() {
            return mSnapshot;
        }

        @Override
        public boolean isCancelled() {
            return false;
        }

        @Override
        public void processNewLines(String[] lines) {
            for (String line : lines) {
                if (line.endsWith("No such file or directory")) {
                    mSnapshot = null;
                    return;
                }

                // ignore header line
                if (line.startsWith("idx")) {
                    continue;
                }

                final String[] cols = line.split(" ");
                if (cols.length < 9) continue;

                // iface and set are currently ignored, which groups those
                // entries together.
                final NetworkSnapshot.Entry entry = new NetworkSnapshot.Entry();

                entry.iface = null; //cols[1];
                entry.uid = Integer.parseInt(cols[3]);
                entry.set = -1; //Integer.parseInt(cols[4]);
                entry.tag = kernelToTag(cols[2]);
                entry.rxBytes = Long.parseLong(cols[5]);
                entry.rxPackets = Long.parseLong(cols[6]);
                entry.txBytes = Long.parseLong(cols[7]);
                entry.txPackets = Long.parseLong(cols[8]);

                mSnapshot.combine(entry);
            }
        }

        /**
         * Convert {@code /proc/} tag format to {@link Integer}. Assumes incoming
         * format like {@code 0x7fffffff00000000}.
         * Matches code in android.server.NetworkManagementSocketTagger
         */
        public static int kernelToTag(String string) {
            int length = string.length();
            if (length > 10) {
                return Long.decode(string.substring(0, length - 8)).intValue();
            } else {
                return 0;
            }
        }
    }

    /**
     * Parsed snapshot of {@link NetworkPanel#PROC_XT_QTAGUID} at specific time.
     */
    private static class NetworkSnapshot implements Iterable<NetworkSnapshot.Entry> {
        private ArrayList<Entry> mStats = new ArrayList<Entry>();

        public final long timestamp;

        /** Single parsed statistics row. */
        public static class Entry {
            public String iface;
            public int uid;
            public int set;
            public int tag;
            public long rxBytes;
            public long rxPackets;
            public long txBytes;
            public long txPackets;

            public boolean isEmpty() {
                return rxBytes == 0 && rxPackets == 0 && txBytes == 0 && txPackets == 0;
            }
        }

        public NetworkSnapshot(long timestamp) {
            this.timestamp = timestamp;
        }

        public void clear() {
            mStats.clear();
        }

        /**
         * Combine the given {@link Entry} with any existing {@link Entry}, or
         * insert if none exists.
         */
        public void combine(Entry entry) {
            final Entry existing = findEntry(entry.iface, entry.uid, entry.set, entry.tag);
            if (existing != null) {
                existing.rxBytes += entry.rxBytes;
                existing.rxPackets += entry.rxPackets;
                existing.txBytes += entry.txBytes;
                existing.txPackets += entry.txPackets;
            } else {
                mStats.add(entry);
            }
        }

        @Override
        public Iterator<Entry> iterator() {
            return mStats.iterator();
        }

        public Entry findEntry(String iface, int uid, int set, int tag) {
            for (Entry entry : mStats) {
                if (entry.uid == uid && entry.set == set && entry.tag == tag
                        && equal(entry.iface, iface)) {
                    return entry;
                }
            }
            return null;
        }

        /**
         * Subtract the two given {@link NetworkSnapshot} objects, returning the
         * delta between them.
         */
        public static NetworkSnapshot subtract(NetworkSnapshot left, NetworkSnapshot right) {
            final NetworkSnapshot result = new NetworkSnapshot(left.timestamp - right.timestamp);

            // for each row on left, subtract value from right side
            for (Entry leftEntry : left) {
                final Entry rightEntry = right.findEntry(
                        leftEntry.iface, leftEntry.uid, leftEntry.set, leftEntry.tag);
                if (rightEntry == null) continue;

                final Entry resultEntry = new Entry();
                resultEntry.iface = leftEntry.iface;
                resultEntry.uid = leftEntry.uid;
                resultEntry.set = leftEntry.set;
                resultEntry.tag = leftEntry.tag;
                resultEntry.rxBytes = leftEntry.rxBytes - rightEntry.rxBytes;
                resultEntry.rxPackets = leftEntry.rxPackets - rightEntry.rxPackets;
                resultEntry.txBytes = leftEntry.txBytes - rightEntry.txBytes;
                resultEntry.txPackets = leftEntry.txPackets - rightEntry.txPackets;

                result.combine(resultEntry);
            }

            return result;
        }
    }

    /**
     * Provider of {@link #mTrackedItems}.
     */
    private class ContentProvider implements IStructuredContentProvider {
        @Override
        public void inputChanged(Viewer viewer, Object oldInput, Object newInput) {
            // pass
        }

        @Override
        public void dispose() {
            // pass
        }

        @Override
        public Object[] getElements(Object inputElement) {
            return mTrackedItems.toArray();
        }
    }

    /**
     * Provider of labels for {@Link TrackedItem} values.
     */
    private static class LabelProvider implements ITableLabelProvider {
        private final DecimalFormat mFormat = new DecimalFormat("#,###");

        @Override
        public Image getColumnImage(Object element, int columnIndex) {
            if (element instanceof TrackedItem) {
                final TrackedItem item = (TrackedItem) element;
                switch (columnIndex) {
                    case 0:
                        return item.colorImage;
                }
            }
            return null;
        }

        @Override
        public String getColumnText(Object element, int columnIndex) {
            if (element instanceof TrackedItem) {
                final TrackedItem item = (TrackedItem) element;
                switch (columnIndex) {
                    case 0:
                        return null;
                    case 1:
                        return item.label;
                    case 2:
                        return mFormat.format(item.rxBytes);
                    case 3:
                        return mFormat.format(item.rxPackets);
                    case 4:
                        return mFormat.format(item.txBytes);
                    case 5:
                        return mFormat.format(item.txPackets);
                }
            }
            return null;
        }

        @Override
        public void addListener(ILabelProviderListener listener) {
            // pass
        }

        @Override
        public void dispose() {
            // pass
        }

        @Override
        public boolean isLabelProperty(Object element, String property) {
            // pass
            return false;
        }

        @Override
        public void removeListener(ILabelProviderListener listener) {
            // pass
        }
    }

    /**
     * Format that displays simplified byte units for when given values are
     * large enough.
     */
    private static class BytesFormat extends NumberFormat {
        private final String[] mUnits;
        private final DecimalFormat mFormat = new DecimalFormat("#.#");

        public BytesFormat(boolean perSecond) {
            if (perSecond) {
                mUnits = new String[] { "B/s", "KB/s", "MB/s" };
            } else {
                mUnits = new String[] { "B", "KB", "MB" };
            }
        }

        @Override
        public StringBuffer format(long number, StringBuffer toAppendTo, FieldPosition pos) {
            double value = Math.abs(number);

            int i = 0;
            while (value > 1024 && i < mUnits.length - 1) {
                value /= 1024;
                i++;
            }

            toAppendTo.append(mFormat.format(value));
            toAppendTo.append(mUnits[i]);

            return toAppendTo;
        }

        @Override
        public StringBuffer format(double number, StringBuffer toAppendTo, FieldPosition pos) {
            return format((long) number, toAppendTo, pos);
        }

        @Override
        public Number parse(String source, ParsePosition parsePosition) {
            return null;
        }
    }

    public static boolean equal(Object a, Object b) {
        return a == b || (a != null && a.equals(b));
    }

    /**
     * Build stub string of requested length, usually for measurement.
     */
    private static String buildSampleText(int length) {
        final StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append("X");
        }
        return builder.toString();
    }

    /**
     * Dataset that contains live measurements. Exposes
     * {@link #removeBefore(long)} to efficiently remove old data, and enables
     * batched {@link #fireDatasetChanged()} events.
     */
    public static class LiveTimeTableXYDataset extends AbstractIntervalXYDataset implements
            TableXYDataset {
        private DefaultKeyedValues2D mValues = new DefaultKeyedValues2D(true);

        /**
         * Caller is responsible for triggering {@link #fireDatasetChanged()}.
         */
        public void addValue(Number value, TimePeriod rowKey, String columnKey) {
            mValues.addValue(value, rowKey, columnKey);
        }

        /**
         * Caller is responsible for triggering {@link #fireDatasetChanged()}.
         */
        public void removeBefore(long beforeMillis) {
            while(mValues.getRowCount() > 0) {
                final TimePeriod period = (TimePeriod) mValues.getRowKey(0);
                if (period.getEnd().getTime() < beforeMillis) {
                    mValues.removeRow(0);
                } else {
                    break;
                }
            }
        }

        public int getColumnIndex(String key) {
            return mValues.getColumnIndex(key);
        }

        public void clear() {
            mValues.clear();
            fireDatasetChanged();
        }

        @Override
        public void fireDatasetChanged() {
            super.fireDatasetChanged();
        }

        @Override
        public int getItemCount() {
            return mValues.getRowCount();
        }

        @Override
        public int getItemCount(int series) {
            return mValues.getRowCount();
        }

        @Override
        public int getSeriesCount() {
            return mValues.getColumnCount();
        }

        @Override
        public Comparable getSeriesKey(int series) {
            return mValues.getColumnKey(series);
        }

        @Override
        public double getXValue(int series, int item) {
            final TimePeriod period = (TimePeriod) mValues.getRowKey(item);
            return period.getStart().getTime();
        }

        @Override
        public double getStartXValue(int series, int item) {
            return getXValue(series, item);
        }

        @Override
        public double getEndXValue(int series, int item) {
            return getXValue(series, item);
        }

        @Override
        public Number getX(int series, int item) {
            return getXValue(series, item);
        }

        @Override
        public Number getStartX(int series, int item) {
            return getXValue(series, item);
        }

        @Override
        public Number getEndX(int series, int item) {
            return getXValue(series, item);
        }

        @Override
        public Number getY(int series, int item) {
            return mValues.getValue(item, series);
        }

        @Override
        public Number getStartY(int series, int item) {
            return getY(series, item);
        }

        @Override
        public Number getEndY(int series, int item) {
            return getY(series, item);
        }
    }
}
