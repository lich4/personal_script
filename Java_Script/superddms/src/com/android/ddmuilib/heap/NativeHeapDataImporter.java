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

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.jface.operation.IRunnableWithProgress;

import java.io.IOException;
import java.io.LineNumberReader;
import java.io.Reader;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.InputMismatchException;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

public class NativeHeapDataImporter implements IRunnableWithProgress {
    private final LineNumberReader mReader;
    private int mStartLineNumber;
    private int mEndLineNumber;

    private NativeHeapSnapshot mSnapshot;

    public NativeHeapDataImporter(Reader stream) {
        mReader = new LineNumberReader(stream);
        mReader.setLineNumber(1); // start numbering at 1
    }

    @Override
    public void run(IProgressMonitor monitor)
            throws InvocationTargetException, InterruptedException {
        monitor.beginTask("Importing Heap Data", IProgressMonitor.UNKNOWN);

        List<NativeAllocationInfo> allocations = new ArrayList<NativeAllocationInfo>();
        try {
            while (true) {
                String line;
                StringBuilder sb = new StringBuilder();

                // read in a sequence of lines corresponding to a single NativeAllocationInfo
                mStartLineNumber = mReader.getLineNumber();
                while ((line = mReader.readLine()) != null) {
                    if (line.trim().length() == 0) {
                        // each block of allocations end with an empty line
                        break;
                    }

                    sb.append(line);
                    sb.append('\n');
                }
                mEndLineNumber = mReader.getLineNumber();

                // parse those lines into a NativeAllocationInfo object
                String allocationBlock = sb.toString();
                if (allocationBlock.trim().length() > 0) {
                    allocations.add(getNativeAllocation(allocationBlock));
                }

                if (line == null) { // EOF
                    break;
                }
            }
        } catch (Exception e) {
            if (e.getMessage() == null) {
                e = new RuntimeException(genericErrorMessage("Unexpected Parse error"));
            }
            throw new InvocationTargetException(e);
        } finally {
            try {
                mReader.close();
            } catch (IOException e) {
                // we can ignore this exception
            }
            monitor.done();
        }

        mSnapshot = new NativeHeapSnapshot(allocations);
    }

    /** Parse a single native allocation dump. This is the complement of
     * {@link NativeAllocationInfo#toString()}.
     *
     * An allocation is of the following form:
     * Allocations: 1
     * Size: 344748
     * Total Size: 344748
     * BeginStackTrace:
     *    40069bd8    /lib/libc_malloc_leak.so --- get_backtrace --- /libc/bionic/malloc_leak.c:258
     *    40069dd8    /lib/libc_malloc_leak.so --- leak_calloc --- /libc/bionic/malloc_leak.c:576
     *    40069bd8    /lib/libc_malloc_leak.so --- 40069bd8 ---
     *    40069dd8    /lib/libc_malloc_leak.so --- 40069dd8 ---
     * EndStackTrace
     * Note that in the above stack trace, the last two lines are examples where the address
     * was not resolved.
     *
     * @param block a string of lines corresponding to a single {@code NativeAllocationInfo}
     * @return parse the input and return the corresponding {@link NativeAllocationInfo}
     * @throws InputMismatchException if there are any parse errors
     */
    private NativeAllocationInfo getNativeAllocation(String block) {
        Scanner sc = new Scanner(block);

        try {
            String kw = sc.next();
            if (!NativeAllocationInfo.ALLOCATIONS_KW.equals(kw)) {
                throw new InputMismatchException(
                        expectedKeywordErrorMessage(NativeAllocationInfo.ALLOCATIONS_KW, kw));
            }

            int allocations = sc.nextInt();

            kw = sc.next();
            if (!NativeAllocationInfo.SIZE_KW.equals(kw)) {
                throw new InputMismatchException(
                        expectedKeywordErrorMessage(NativeAllocationInfo.SIZE_KW, kw));
            }

            int size = sc.nextInt();

            kw = sc.next();
            if (!NativeAllocationInfo.TOTAL_SIZE_KW.equals(kw)) {
                throw new InputMismatchException(
                        expectedKeywordErrorMessage(NativeAllocationInfo.TOTAL_SIZE_KW, kw));
            }

            int totalSize = sc.nextInt();
            if (totalSize != size * allocations) {
                throw new InputMismatchException(
                        genericErrorMessage("Total Size does not match size * # of allocations"));
            }

            NativeAllocationInfo info = new NativeAllocationInfo(size, allocations);

            kw = sc.next();
            if (!NativeAllocationInfo.BEGIN_STACKTRACE_KW.equals(kw)) {
                throw new InputMismatchException(
                        expectedKeywordErrorMessage(NativeAllocationInfo.BEGIN_STACKTRACE_KW, kw));
            }

            List<NativeStackCallInfo> stackInfo = new ArrayList<NativeStackCallInfo>();
            Pattern endTracePattern = Pattern.compile(NativeAllocationInfo.END_STACKTRACE_KW);


            while (true) {
                long address = sc.nextLong(16);
                info.addStackCallAddress(address);

                String library = sc.next();
                sc.next();  // ignore "---"
                String method = scanTillSeparator(sc, "---");

                String filename = "";
                if (!isUnresolved(method, address)) {
                    filename = sc.next();
                }

                stackInfo.add(new NativeStackCallInfo(address, library, method, filename));

                if (sc.hasNext(endTracePattern)) {
                    break;
                }
            }

            info.setResolvedStackCall(stackInfo);
            return info;
        } finally {
            sc.close();
        }
    }

    private String scanTillSeparator(Scanner sc, String separator) {
        StringBuilder sb = new StringBuilder();

        while (true) {
            String token = sc.next();
            if (token.equals(separator)) {
                break;
            }

            sb.append(token);

            // We do not know the exact delimiter that was skipped over, but we know
            // that there was atleast 1 whitespace. Add a single whitespace character
            // to account for this.
            sb.append(' ');
        }

        return sb.toString().trim();
    }

    private boolean isUnresolved(String method, long address) {
        // a method is unresolved if it is just the hex representation of the address
        return Long.toString(address, 16).equals(method);
    }

    private String genericErrorMessage(String message) {
        return String.format("%1$s between lines %2$d and %3$d",
                message, mStartLineNumber, mEndLineNumber);
    }

    private String expectedKeywordErrorMessage(String expected, String actual) {
        return String.format("Expected keyword '%1$s', saw '%2$s' between lines %3$d to %4$d.",
                expected, actual, mStartLineNumber, mEndLineNumber);
    }

    public NativeHeapSnapshot getImportedSnapshot() {
        return mSnapshot;
    }
}
