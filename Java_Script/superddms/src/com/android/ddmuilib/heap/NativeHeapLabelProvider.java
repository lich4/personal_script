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

package com.android.ddmuilib.heap;

import com.android.ddmlib.NativeAllocationInfo;
import com.android.ddmlib.NativeStackCallInfo;

import org.eclipse.jface.viewers.ITableLabelProvider;
import org.eclipse.jface.viewers.LabelProvider;
import org.eclipse.swt.graphics.Image;

/**
 * A Label Provider for the Native Heap TreeViewer in {@link NativeHeapPanel}.
 */
public class NativeHeapLabelProvider extends LabelProvider implements ITableLabelProvider {
    private long mTotalSize;

    @Override
    public Image getColumnImage(Object arg0, int arg1) {
        return null;
    }

    @Override
    public String getColumnText(Object element, int index) {
        if (element instanceof NativeAllocationInfo) {
            return getColumnTextForNativeAllocation((NativeAllocationInfo) element, index);
        }

        if (element instanceof NativeLibraryAllocationInfo) {
            return getColumnTextForNativeLibrary((NativeLibraryAllocationInfo) element, index);
        }

        return null;
    }

    private String getColumnTextForNativeAllocation(NativeAllocationInfo info, int index) {
        NativeStackCallInfo stackInfo = info.getRelevantStackCallInfo();

        switch (index) {
            case 0:
                return stackInfo == null ? stackResolutionStatus(info) : stackInfo.getLibraryName();
            case 1:
                return Integer.toString(info.getSize() * info.getAllocationCount());
            case 2:
                return getPercentageString(info.getSize() * info.getAllocationCount(), mTotalSize);
            case 3:
                String prefix = "";
                if (!info.isZygoteChild()) {
                    prefix = "Z ";
                }
                return prefix + Integer.toString(info.getAllocationCount());
            case 4:
                return Integer.toString(info.getSize());
            case 5:
                return stackInfo == null ? stackResolutionStatus(info) : stackInfo.getMethodName();
            default:
                return null;
        }
    }

    private String getColumnTextForNativeLibrary(NativeLibraryAllocationInfo info, int index) {
        switch (index) {
            case 0:
                return info.getLibraryName();
            case 1:
                return Long.toString(info.getTotalSize());
            case 2:
                return getPercentageString(info.getTotalSize(), mTotalSize);
            default:
                return null;
        }
    }

    private String getPercentageString(long size, long total) {
        if (total == 0) {
            return "";
        }

        return String.format("%.1f%%", (float)(size * 100)/(float)total);
    }

    private String stackResolutionStatus(NativeAllocationInfo info) {
        if (info.isStackCallResolved()) {
            return "?"; // resolved and unknown
        } else {
            return "Resolving...";  // still resolving...
        }
    }

    /**
     * Set the total size of the heap dump for use in percentage calculations.
     * This value should be set whenever the input to the tree changes so that the percentages
     * are computed correctly.
     */
    public void setTotalSize(long totalSize) {
        mTotalSize = totalSize;
    }
}
