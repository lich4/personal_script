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

import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * A Native Heap Snapshot models a single heap dump.
 *
 * It primarily consists of a list of {@link NativeAllocationInfo} objects. From this list,
 * other objects of interest to the UI are computed and cached for future use.
 */
public class NativeHeapSnapshot {
    private static final NumberFormat NUMBER_FORMATTER = NumberFormat.getInstance();

    private List<NativeAllocationInfo> mHeapAllocations;
    private List<NativeLibraryAllocationInfo> mHeapAllocationsByLibrary;

    private List<NativeAllocationInfo> mNonZygoteHeapAllocations;
    private List<NativeLibraryAllocationInfo> mNonZygoteHeapAllocationsByLibrary;

    private long mTotalSize;

    public NativeHeapSnapshot(List<NativeAllocationInfo> heapAllocations) {
        mHeapAllocations = heapAllocations;

        // precompute the total size as this is always needed.
        mTotalSize = getTotalMemory(heapAllocations);
    }

    protected long getTotalMemory(Collection<NativeAllocationInfo> heapSnapshot) {
        long total = 0;

        for (NativeAllocationInfo info : heapSnapshot) {
            total += info.getAllocationCount() * info.getSize();
        }

        return total;
    }

    public List<NativeAllocationInfo> getAllocations() {
        return mHeapAllocations;
    }

    public List<NativeLibraryAllocationInfo> getAllocationsByLibrary() {
        if (mHeapAllocationsByLibrary != null) {
            return mHeapAllocationsByLibrary;
        }

        List<NativeLibraryAllocationInfo> heapAllocations =
                NativeLibraryAllocationInfo.constructFrom(mHeapAllocations);

        // cache for future uses only if it is fully resolved.
        if (isFullyResolved(heapAllocations)) {
            mHeapAllocationsByLibrary = heapAllocations;
        }

        return heapAllocations;
    }

    private boolean isFullyResolved(List<NativeLibraryAllocationInfo> heapAllocations) {
        for (NativeLibraryAllocationInfo info : heapAllocations) {
            if (info.getLibraryName().equals(NativeLibraryAllocationInfo.UNRESOLVED_LIBRARY_NAME)) {
                return false;
            }
        }

        return true;
    }

    public long getTotalSize() {
        return mTotalSize;
    }

    public String getFormattedMemorySize() {
        return String.format("%s bytes", formatMemorySize(getTotalSize()));
    }

    protected String formatMemorySize(long memSize) {
        return NUMBER_FORMATTER.format(memSize);
    }

    public List<NativeAllocationInfo> getNonZygoteAllocations() {
        if (mNonZygoteHeapAllocations != null) {
            return mNonZygoteHeapAllocations;
        }

        // filter out all zygote allocations
        mNonZygoteHeapAllocations = new ArrayList<NativeAllocationInfo>();
        for (NativeAllocationInfo info : mHeapAllocations) {
            if (info.isZygoteChild()) {
                mNonZygoteHeapAllocations.add(info);
            }
        }

        return mNonZygoteHeapAllocations;
    }

    public List<NativeLibraryAllocationInfo> getNonZygoteAllocationsByLibrary() {
        if (mNonZygoteHeapAllocationsByLibrary != null) {
            return mNonZygoteHeapAllocationsByLibrary;
        }

        List<NativeLibraryAllocationInfo> heapAllocations =
                NativeLibraryAllocationInfo.constructFrom(getNonZygoteAllocations());

        // cache for future uses only if it is fully resolved.
        if (isFullyResolved(heapAllocations)) {
            mNonZygoteHeapAllocationsByLibrary = heapAllocations;
        }

        return heapAllocations;
    }
}
