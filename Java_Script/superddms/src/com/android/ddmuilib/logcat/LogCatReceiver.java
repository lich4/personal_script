/*
 * Copyright (C) 2011 The Android Open Source Project
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

package com.android.ddmuilib.logcat;

import com.android.ddmlib.IDevice;
import com.android.ddmlib.Log.LogLevel;
import com.android.ddmlib.logcat.LogCatListener;
import com.android.ddmlib.logcat.LogCatMessage;
import com.android.ddmlib.logcat.LogCatReceiverTask;

import org.eclipse.jface.preference.IPreferenceStore;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A class to monitor a device for logcat messages. It stores the received
 * log messages in a circular buffer.
 */
public final class LogCatReceiver implements LogCatListener {
    private static LogCatMessage DEVICE_DISCONNECTED_MESSAGE =
            new LogCatMessage(LogLevel.ERROR, "", "", "",
                    "", "", "Device disconnected");

    private LogCatMessageList mLogMessages;
    private IDevice mCurrentDevice;
    private LogCatReceiverTask mLogCatReceiverTask;
    private Set<ILogCatBufferChangeListener> mLogCatMessageListeners;
    private IPreferenceStore mPrefStore;

    /**
     * Construct a LogCat message receiver for provided device. This will launch a
     * logcat command on the device, and monitor the output of that command in
     * a separate thread. All logcat messages are then stored in a circular
     * buffer, which can be retrieved using {@link LogCatReceiver#getMessages()}.
     * @param device device to monitor for logcat messages
     * @param prefStore
     */
    public LogCatReceiver(IDevice device, IPreferenceStore prefStore) {
        mCurrentDevice = device;
        mPrefStore = prefStore;

        mLogCatMessageListeners = new HashSet<ILogCatBufferChangeListener>();
        mLogMessages = new LogCatMessageList(getFifoSize());

        startReceiverThread();
    }

    /**
     * Stop receiving messages from currently active device.
     */
    public void stop() {
        if (mLogCatReceiverTask != null) {
            /* stop the current logcat command */
            mLogCatReceiverTask.removeLogCatListener(this);
            mLogCatReceiverTask.stop();
            mLogCatReceiverTask = null;

            // add a message to the log indicating that the device has been disconnected.
            log(Collections.singletonList(DEVICE_DISCONNECTED_MESSAGE));
        }

        mCurrentDevice = null;
    }

    private int getFifoSize() {
        int n = mPrefStore.getInt(LogCatMessageList.MAX_MESSAGES_PREFKEY);
        return n == 0 ? LogCatMessageList.MAX_MESSAGES_DEFAULT : n;
    }

    private void startReceiverThread() {
        if (mCurrentDevice == null) {
            return;
        }

        mLogCatReceiverTask = new LogCatReceiverTask(mCurrentDevice);
        mLogCatReceiverTask.addLogCatListener(this);

        Thread t = new Thread(mLogCatReceiverTask);
        t.setName("LogCat output receiver for " + mCurrentDevice.getSerialNumber());
        t.start();
    }

    @Override
    public void log(List<LogCatMessage> newMessages) {
        List<LogCatMessage> deletedMessages;
        synchronized (mLogMessages) {
            deletedMessages = mLogMessages.ensureSpace(newMessages.size());
            mLogMessages.appendMessages(newMessages);
        }
        sendLogChangedEvent(newMessages, deletedMessages);
    }

    /**
     * Get the list of logcat messages received from currently active device.
     * @return list of messages if currently listening, null otherwise
     */
    public LogCatMessageList getMessages() {
        return mLogMessages;
    }

    /**
     * Clear the list of messages received from the currently active device.
     */
    public void clearMessages() {
        mLogMessages.clear();
    }

    /**
     * Add to list of message event listeners.
     * @param l listener to notified when messages are received from the device
     */
    public void addMessageReceivedEventListener(ILogCatBufferChangeListener l) {
        mLogCatMessageListeners.add(l);
    }

    public void removeMessageReceivedEventListener(ILogCatBufferChangeListener l) {
        mLogCatMessageListeners.remove(l);
    }

    private void sendLogChangedEvent(List<LogCatMessage> addedMessages,
            List<LogCatMessage> deletedMessages) {
        for (ILogCatBufferChangeListener l : mLogCatMessageListeners) {
            l.bufferChanged(addedMessages, deletedMessages);
        }
    }

    /**
     * Resize the internal FIFO.
     * @param size new size
     */
    public void resizeFifo(int size) {
        mLogMessages.resize(size);
    }
}
