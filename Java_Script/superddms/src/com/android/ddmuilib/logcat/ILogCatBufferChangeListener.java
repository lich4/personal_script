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

import java.util.List;

/**
 * Listeners interested in changes in the logcat buffer should implement this interface.
 */
public interface ILogCatBufferChangeListener {
    /**
     * Called when the logcat buffer changes.
     * @param addedMessages list of messages that were added to the logcat buffer
     * @param deletedMessages list of messages that were removed from the logcat buffer
     */
    void bufferChanged(List<LogCatMessage> addedMessages, List<LogCatMessage> deletedMessages);
}
