/*
 * Copyright (C) 2013 The Android Open Source Project
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

import java.util.List;

/**
 * {@link NativeDiffAllocationInfo} stores the difference in the allocation
 * counts between two allocations with the same stack trace.
 *
 * Since only the allocation counts are different, it delegates all other functionality to
 * one of the allocations and just maintains the allocation count.
 */
public class NativeDiffAllocationInfo extends NativeAllocationInfo {
    private final NativeAllocationInfo info;

    public NativeDiffAllocationInfo(NativeAllocationInfo cur, NativeAllocationInfo prev) {
        super(cur.getSize(), getNewAllocations(cur, prev));
        info = cur;
    }

    private static int getNewAllocations(NativeAllocationInfo n1, NativeAllocationInfo n2) {
        return n1.getAllocationCount() - n2.getAllocationCount();
    }

    @Override
    public boolean isStackCallResolved() {
        return info.isStackCallResolved();
    }

    @Override
    public List<Long> getStackCallAddresses() {
        return info.getStackCallAddresses();
    }

    @Override
    public synchronized List<NativeStackCallInfo> getResolvedStackCall() {
        return info.getResolvedStackCall();
    }

    @Override
    public synchronized NativeStackCallInfo getRelevantStackCallInfo() {
        return info.getRelevantStackCallInfo();
    }

    @Override
    public boolean isZygoteChild() {
        return info.isZygoteChild();
    }
}
