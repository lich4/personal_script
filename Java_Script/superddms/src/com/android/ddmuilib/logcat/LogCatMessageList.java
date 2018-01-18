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

import com.android.ddmlib.logcat.LogCatMessage;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

/**
 * Container for a list of log messages. The list of messages are
 * maintained in a circular buffer (FIFO).
 */
public final class LogCatMessageList {
    /** Preference key for size of the FIFO. */
    public static final String MAX_MESSAGES_PREFKEY =
            "logcat.messagelist.max.size";

    /** Default value for max # of messages. */
    public static final int MAX_MESSAGES_DEFAULT = 5000;

    private int mFifoSize;
    private BlockingQueue<LogCatMessage> mQ;

    /**
     * Construct an empty message list.
     * @param maxMessages capacity of the circular buffer
     */
    public LogCatMessageList(int maxMessages) {
        mFifoSize = maxMessages;

        mQ = new ArrayBlockingQueue<LogCatMessage>(mFifoSize);
    }

    /**
     * Resize the message list.
     * @param n new size for the list
     */
    public synchronized void resize(int n) {
        mFifoSize = n;

        if (mFifoSize > mQ.size()) {
            /* if resizing to a bigger fifo, we can copy over all elements from the current mQ */
            mQ = new ArrayBlockingQueue<LogCatMessage>(mFifoSize, true, mQ);
        } else {
            /* for a smaller fifo, copy over the last n entries */
            LogCatMessage[] curMessages = mQ.toArray(new LogCatMessage[mQ.size()]);
            mQ = new ArrayBlockingQueue<LogCatMessage>(mFifoSize);
            for (int i = curMessages.length - mFifoSize; i < curMessages.length; i++) {
                mQ.offer(curMessages[i]);
            }
        }
    }

    /**
     * Append a message to the list. If the list is full, the first
     * message will be popped off of it.
     * @param m log to be inserted
     */
    public synchronized void appendMessages(final List<LogCatMessage> messages) {
        ensureSpace(messages.size());
        for (LogCatMessage m: messages) {
            mQ.offer(m);
        }
    }

    /**
     * Ensure that there is sufficient space for given number of messages.
     * @return list of messages that were deleted to create additional space.
     */
    public synchronized List<LogCatMessage> ensureSpace(int messageCount) {
        List<LogCatMessage> l = new ArrayList<LogCatMessage>(messageCount);

        while (mQ.remainingCapacity() < messageCount) {
            l.add(mQ.poll());
        }

        return l;
    }

    /**
     * Returns the number of additional elements that this queue can
     * ideally (in the absence of memory or resource constraints)
     * accept without blocking.
     * @return the remaining capacity
     */
    public synchronized int remainingCapacity() {
        return mQ.remainingCapacity();
    }

    /** Clear all messages in the list. */
    public synchronized void clear() {
        mQ.clear();
    }

    /** Obtain a copy of the message list. */
    public synchronized List<LogCatMessage> getAllMessages() {
        return new ArrayList<LogCatMessage>(mQ);
    }
}
