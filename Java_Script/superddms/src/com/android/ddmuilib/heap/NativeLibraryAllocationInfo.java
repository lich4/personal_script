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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A heap dump representation where each call site is associated with its source library.
 */
public final class NativeLibraryAllocationInfo {
    /** Library name to use when grouping before symbol resolution is complete. */
    public static final String UNRESOLVED_LIBRARY_NAME = "Resolving..";

    /** Any call site that cannot be resolved to a specific library goes under this name. */
    private static final String UNKNOWN_LIBRARY_NAME = "unknown";

    private final String mLibraryName;
    private final List<NativeAllocationInfo> mHeapAllocations;
    private int mTotalSize;

    private NativeLibraryAllocationInfo(String libraryName) {
        mLibraryName = libraryName;
        mHeapAllocations = new ArrayList<NativeAllocationInfo>();
    }

    private void addAllocation(NativeAllocationInfo info) {
        mHeapAllocations.add(info);
    }

    private void updateTotalSize() {
        mTotalSize = 0;
        for (NativeAllocationInfo i : mHeapAllocations) {
            mTotalSize += i.getAllocationCount() * i.getSize();
        }
    }

    public String getLibraryName() {
        return mLibraryName;
    }

    public long getTotalSize() {
        return mTotalSize;
    }

    public List<NativeAllocationInfo> getAllocations() {
        return mHeapAllocations;
    }

    /**
     * Factory method to create a list of {@link NativeLibraryAllocationInfo} objects,
     * given the list of {@link NativeAllocationInfo} objects.
     *
     * If the {@link NativeAllocationInfo} objects do not have their symbols resolved,
     * then they are grouped under the library {@link #UNRESOLVED_LIBRARY_NAME}. If they do
     * have their symbols resolved, but map to an unknown library, then they are grouped under
     * the library {@link #UNKNOWN_LIBRARY_NAME}.
     */
    public static List<NativeLibraryAllocationInfo> constructFrom(
            List<NativeAllocationInfo> allocations) {
        if (allocations == null) {
            return null;
        }

        Map<String, NativeLibraryAllocationInfo> allocationsByLibrary =
                new HashMap<String, NativeLibraryAllocationInfo>();

        // go through each native allocation and assign it to the appropriate library
        for (NativeAllocationInfo info : allocations) {
            String libName = UNRESOLVED_LIBRARY_NAME;

            if (info.isStackCallResolved()) {
                NativeStackCallInfo relevantStackCall = info.getRelevantStackCallInfo();
                if (relevantStackCall != null) {
                    libName = relevantStackCall.getLibraryName();
                } else {
                    libName = UNKNOWN_LIBRARY_NAME;
                }
            }

            addtoLibrary(allocationsByLibrary, libName, info);
        }

        List<NativeLibraryAllocationInfo> libraryAllocations =
                new ArrayList<NativeLibraryAllocationInfo>(allocationsByLibrary.values());

        // now update some summary statistics for each library
        for (NativeLibraryAllocationInfo l : libraryAllocations) {
            l.updateTotalSize();
        }

        // finally, sort by total size
        Collections.sort(libraryAllocations, new Comparator<NativeLibraryAllocationInfo>() {
                    @Override
                    public int compare(NativeLibraryAllocationInfo o1,
                            NativeLibraryAllocationInfo o2) {
                        return (int) (o2.getTotalSize() - o1.getTotalSize());
                    }
                });

        return libraryAllocations;
    }

    private static void addtoLibrary(Map<String, NativeLibraryAllocationInfo> libraryAllocations,
            String libName, NativeAllocationInfo info) {
        NativeLibraryAllocationInfo libAllocationInfo = libraryAllocations.get(libName);
        if (libAllocationInfo == null) {
            libAllocationInfo = new NativeLibraryAllocationInfo(libName);
            libraryAllocations.put(libName, libAllocationInfo);
        }

        libAllocationInfo.addAllocation(info);
    }
}
