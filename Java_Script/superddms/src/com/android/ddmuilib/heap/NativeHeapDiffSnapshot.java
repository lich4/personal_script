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
import com.google.common.collect.Sets;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Models a heap snapshot that is the difference between two snapshots.
 */
public class NativeHeapDiffSnapshot extends NativeHeapSnapshot {
    private long mCommonAllocationsTotalMemory;

    public NativeHeapDiffSnapshot(NativeHeapSnapshot newSnapshot, NativeHeapSnapshot oldSnapshot) {
        // The diff snapshots behaves like a snapshot that only contains the new allocations
        // not present in the old snapshot
        super(getNewAllocations(newSnapshot, oldSnapshot));

        Set<NativeAllocationInfo> commonAllocations =
                new HashSet<NativeAllocationInfo>(oldSnapshot.getAllocations());
        commonAllocations.retainAll(newSnapshot.getAllocations());

        // Memory common between the old and new snapshots
        mCommonAllocationsTotalMemory = getTotalMemory(commonAllocations);
    }

    private static List<NativeAllocationInfo> getNewAllocations(NativeHeapSnapshot newSnapshot,
            NativeHeapSnapshot oldSnapshot) {
        Set<NativeAllocationInfo> allocations =
                new HashSet<NativeAllocationInfo>(newSnapshot.getAllocations());

        // compute new allocations
        allocations.removeAll(oldSnapshot.getAllocations());

        // Account for allocations with the same stack trace that were
        // present in the older set of allocations.
        // e.g. A particular stack trace might have had 3 allocations in snapshot 1,
        // and 2 more in snapshot 2. We only want to show the new allocations (just the 2 from
        // snapshot 2). However, the way the allocations are stored, in snapshot 2, we'll see
        // 5 allocations at the stack trace. We need to subtract out the 3 from the first allocation
        Set<NativeAllocationInfo> onlyInPrevious =
                new HashSet<NativeAllocationInfo>(oldSnapshot.getAllocations());
        Set<NativeAllocationInfo> newAllocations =
                Sets.newHashSetWithExpectedSize(allocations.size());

        onlyInPrevious.removeAll(newSnapshot.getAllocations());
        for (NativeAllocationInfo current : allocations) {
            NativeAllocationInfo old = getOldAllocationWithSameStack(current, onlyInPrevious);
            if (old == null) {
                newAllocations.add(current);
            } else if (current.getAllocationCount() > old.getAllocationCount()) {
                newAllocations.add(new NativeDiffAllocationInfo(current, old));
            }
        }

        return new ArrayList<NativeAllocationInfo>(newAllocations);
    }

    private static NativeAllocationInfo getOldAllocationWithSameStack(
            NativeAllocationInfo info,
            Set<NativeAllocationInfo> allocations) {
        for (NativeAllocationInfo a : allocations) {
            if (info.getSize() == a.getSize() && info.stackEquals(a)) {
                return a;
            }
        }

        return null;
    }

    @Override
    public String getFormattedMemorySize() {
        // for a diff snapshot, we report the following string for display:
        //       xxx bytes new allocation + yyy bytes retained from previous allocation
        //          = zzz bytes total

        long newAllocations = getTotalSize();
        return String.format("%s bytes new + %s bytes retained = %s bytes total",
                formatMemorySize(newAllocations),
                formatMemorySize(mCommonAllocationsTotalMemory),
                formatMemorySize(newAllocations + mCommonAllocationsTotalMemory));
    }
}
