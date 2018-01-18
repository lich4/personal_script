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

package com.android.ddmuilib;

import java.util.regex.Pattern;

/**
 * {@link AbstractBufferFindTarget} implements methods to find items inside a buffer. It takes
 * care of the logic to search backwards/forwards in the buffer, wrapping around when necessary.
 * The actual contents of the buffer should be provided by the classes that extend this.
 */
public abstract class AbstractBufferFindTarget implements IFindTarget {
    private int mCurrentSearchIndex;

    // Single element cache of the last search regex
    private Pattern mLastSearchPattern;
    private String mLastSearchText;

    @Override
    public boolean findAndSelect(String text, boolean isNewSearch, boolean searchForward) {
        boolean found = false;
        int maxIndex = getItemCount();

        synchronized (this) {
            // Find starting index for this search
            if (isNewSearch) {
                // for new searches, start from an appropriate place as provided by the delegate
                mCurrentSearchIndex = getStartingIndex();
            } else {
                // for ongoing searches (finding next match for the same term), continue from
                // the current result index
                mCurrentSearchIndex = getNext(mCurrentSearchIndex, searchForward, maxIndex);
            }

            // Create a regex pattern based on the search term.
            Pattern pattern;
            if (text.equals(mLastSearchText)) {
                pattern = mLastSearchPattern;
            } else {
                pattern = Pattern.compile(text, Pattern.CASE_INSENSITIVE);
                mLastSearchPattern = pattern;
                mLastSearchText = text;
            }

            // Iterate through the list of items. The search ends if we have gone through
            // all items once.
            int index = mCurrentSearchIndex;
            do {
                String msgText = getItem(mCurrentSearchIndex);
                if (msgText != null && pattern.matcher(msgText).find()) {
                    found = true;
                    break;
                }

                mCurrentSearchIndex = getNext(mCurrentSearchIndex, searchForward, maxIndex);
            } while (index != mCurrentSearchIndex); // loop through entire contents once
        }

        if (found) {
            selectAndReveal(mCurrentSearchIndex);
        }

        return found;
    }

    /** Indicate that the log buffer has scrolled by certain number of elements */
    public void scrollBy(int delta) {
        synchronized (this) {
            if (mCurrentSearchIndex > 0) {
                mCurrentSearchIndex = Math.max(0, mCurrentSearchIndex - delta);
            }
        }
    }

    private int getNext(int index, boolean searchForward, int max) {
        // increment or decrement index
        index = searchForward ? index + 1 : index - 1;

        // take care of underflow
        if (index == -1) {
            index = max - 1;
        }

        // ..and overflow
        if (index == max) {
            index = 0;
        }

        return index;
    }

    /** Obtain the number of items in the buffer */
    public abstract int getItemCount();

    /** Obtain the item at given index */
    public abstract String getItem(int index);

    /** Select and reveal the item at given index */
    public abstract void selectAndReveal(int index);

    /** Obtain the index from which search should begin */
    public abstract int getStartingIndex();
}
