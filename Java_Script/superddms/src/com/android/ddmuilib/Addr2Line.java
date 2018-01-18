/*
 * Copyright (C) 2007 The Android Open Source Project
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

import com.android.annotations.NonNull;
import com.android.annotations.Nullable;
import com.android.ddmlib.Log;
import com.android.ddmlib.NativeLibraryMapInfo;
import com.android.ddmlib.NativeStackCallInfo;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

/**
 * Represents an addr2line process to get filename/method information from a
 * memory address.<br>
 * Each process can only handle one library, which should be provided when
 * creating a new process.<br>
 * <br>
 * The processes take some time to load as they need to parse the library files.
 * For this reason, processes cannot be manually started. Instead the class
 * keeps an internal list of processes and one asks for a process for a specific
 * library, using <code>getProcess(String library)<code>.<br></br>
 * Internally, the processes are started in pipe mode to be able to query them
 * with multiple addresses.
 */
public class Addr2Line {
    private static final String ANDROID_SYMBOLS_ENVVAR = "ANDROID_SYMBOLS";

    private static final String LIBRARY_NOT_FOUND_MESSAGE_FORMAT =
            "Unable to locate library %s on disk. Addresses mapping to this library "
          + "will not be resolved. In order to fix this, set the the library search path "
          + "in the UI, or set the environment variable " + ANDROID_SYMBOLS_ENVVAR + ".";

    /**
     * Loaded processes list. This is also used as a locking object for any
     * methods dealing with starting/stopping/creating processes/querying for
     * method.
     */
    private static final HashMap<String, Addr2Line> sProcessCache =
            new HashMap<String, Addr2Line>();

    /**
     * byte array representing a carriage return. Used to push addresses in the
     * process pipes.
     */
    private static final byte[] sCrLf = {
        '\n'
    };

    /** Path to the library */
    private NativeLibraryMapInfo mLibrary;

    /** addr2line command to execute */
    private String mAddr2LineCmd;

    /** the command line process */
    private Process mProcess;

    /** buffer to read the result of the command line process from */
    private BufferedReader mResultReader;

    /**
     * output stream to provide new addresses to decode to the command line
     * process
     */
    private BufferedOutputStream mAddressWriter;

    private static final String DEFAULT_LIBRARY_SYMBOLS_FOLDER;
    static {
        String symbols = System.getenv(ANDROID_SYMBOLS_ENVVAR);
        if (symbols == null) {
            DEFAULT_LIBRARY_SYMBOLS_FOLDER = DdmUiPreferences.getSymbolDirectory();
        } else {
            DEFAULT_LIBRARY_SYMBOLS_FOLDER = symbols;
        }
    }

    private static List<String> mLibrarySearchPaths = new ArrayList<String>();

    /**
     * Set the search path where libraries should be found.
     * @param path search path to use, can be a colon separated list of paths if multiple folders
     * should be searched
     */
    public static void setSearchPath(String path) {
        mLibrarySearchPaths.clear();
        mLibrarySearchPaths.addAll(Arrays.asList(path.split(":")));
    }

    /**
     * Returns the instance of an Addr2Line process for the specified library
     * and abi.
     * <br>The library should be in a format that makes<br>
     * <code>$ANDROID_PRODUCT_OUT + "/symbols" + library</code> a valid file.
     *
     * @param library the library in which to look for addresses.
     * @param abi indicates which underlying addr2line command to use.
     * @return a new Addr2Line object representing a started process, ready to
     *         be queried for addresses. If any error happened when launching a
     *         new process, <code>null</code> will be returned.
     */
    public static Addr2Line getProcess(@NonNull final NativeLibraryMapInfo library, @Nullable String abi) {
        String libName = library.getLibraryName();

        // synchronize around the hashmap object
        if (libName != null) {
            synchronized (sProcessCache) {
                // look for an existing process
                Addr2Line process = sProcessCache.get(libName);

                // if we don't find one, we create it
                if (process == null) {
                    process = new Addr2Line(library, abi);

                    // then we start it
                    boolean status = process.start();

                    if (status) {
                        // if starting the process worked, then we add it to the
                        // list.
                        sProcessCache.put(libName, process);
                    } else {
                        // otherwise we just drop the object, to return null
                        process = null;
                    }
                }
                // return the process
                return process;
            }
        }
        return null;
    }

    /**
     * Construct the object with a library name and abi. The library should be present
     * in the search path as provided by ANDROID_SYMBOLS, ANDROID_OUT/symbols, or in the user
     * provided search path.
     *
     * @param library the library in which to look for address.
     * @param abi indicates which underlying addr2line command to use.
     */
    private Addr2Line(@NonNull final NativeLibraryMapInfo library, @Nullable String abi) {
        mLibrary = library;

        // Set the addr2line command based on the abi.
        if (abi == null || abi.startsWith("32")) {
            Log.d("ddm-Addr2Line", "Using 32 bit addr2line command");
            mAddr2LineCmd = System.getenv("ANDROID_ADDR2LINE");
            if (mAddr2LineCmd == null) {
                mAddr2LineCmd = DdmUiPreferences.getAddr2Line();
            }
        } else {
            Log.d("ddm-Addr2Line", "Using 64 bit addr2line command");
            mAddr2LineCmd = System.getenv("ANDROID_ADDR2LINE64");
            if (mAddr2LineCmd == null) {
                mAddr2LineCmd = DdmUiPreferences.getAddr2Line64();
            }
        }
    }

    /**
     * Search for the library in the library search path and obtain the full path to where it
     * is found.
     * @return fully resolved path to the library if found in search path, null otherwise
     */
    private String getLibraryPath(String library) {
        // first check the symbols folder
        String path = DEFAULT_LIBRARY_SYMBOLS_FOLDER + library;
        if (new File(path).exists()) {
            return path;
        }

        for (String p : mLibrarySearchPaths) {
            // try appending the full path on device
            String fullPath = p + "/" + library;
            if (new File(fullPath).exists()) {
                return fullPath;
            }

            // try appending basename(library)
            fullPath = p + "/" + new File(library).getName();
            if (new File(fullPath).exists()) {
                return fullPath;
            }
        }

        return null;
    }

    /**
     * Starts the command line process.
     *
     * @return true if the process was started, false if it failed to start, or
     *         if there was any other errors.
     */
    private boolean start() {
        // because this is only called from getProcess() we know we don't need
        // to synchronize this code.

        // build the command line
        String[] command = new String[5];
        command[0] = mAddr2LineCmd;
        command[1] = "-C";
        command[2] = "-f";
        command[3] = "-e";

        String fullPath = getLibraryPath(mLibrary.getLibraryName());
        if (fullPath == null) {
            String msg = String.format(LIBRARY_NOT_FOUND_MESSAGE_FORMAT, mLibrary.getLibraryName());
            Log.e("ddm-Addr2Line", msg);
            return false;
        }

        command[4] = fullPath;

        try {
            // attempt to start the process
            mProcess = Runtime.getRuntime().exec(command);

            if (mProcess != null) {
                // get the result reader
                InputStreamReader is = new InputStreamReader(mProcess
                        .getInputStream());
                mResultReader = new BufferedReader(is);

                // get the outstream to write the addresses
                mAddressWriter = new BufferedOutputStream(mProcess
                        .getOutputStream());

                // check our streams are here
                if (mResultReader == null || mAddressWriter == null) {
                    // not here? stop the process and return false;
                    mProcess.destroy();
                    mProcess = null;
                    return false;
                }

                // return a success
                return true;
            }

        } catch (IOException e) {
            // log the error
            String msg = String.format(
                    "Error while trying to start %1$s process for library %2$s",
                    mAddr2LineCmd, mLibrary);
            Log.e("ddm-Addr2Line", msg);

            // drop the process just in case
            if (mProcess != null) {
                mProcess.destroy();
                mProcess = null;
            }
        }

        // we can be here either cause the allocation of mProcess failed, or we
        // caught an exception
        return false;
    }

    /**
     * Stops the command line process.
     */
    public void stop() {
        synchronized (sProcessCache) {
            if (mProcess != null) {
                // remove the process from the list
                sProcessCache.remove(mLibrary);

                // then stops the process
                mProcess.destroy();

                // set the reference to null.
                // this allows to make sure another thread calling getAddress()
                // will not query a stopped thread
                mProcess = null;
            }
        }
    }

    /**
     * Stops all current running processes.
     */
    public static void stopAll() {
        // because of concurrent access (and our use of HashMap.values()), we
        // can't rely on the synchronized inside stop(). We need to put one
        // around the whole loop.
        synchronized (sProcessCache) {
            // just a basic loop on all the values in the hashmap and call to
            // stop();
            Collection<Addr2Line> col = sProcessCache.values();
            for (Addr2Line a2l : col) {
                a2l.stop();
            }
        }
    }

    /**
     * Looks up an address and returns method name, source file name, and line
     * number.
     *
     * @param addr the address to look up
     * @return a BacktraceInfo object containing the method/filename/linenumber
     *         or null if the process we stopped before the query could be
     *         processed, or if an IO exception happened.
     */
    public NativeStackCallInfo getAddress(long addr) {
        long offset = addr - mLibrary.getStartAddress();

        // even though we don't access the hashmap object, we need to
        // synchronized on it to prevent
        // another thread from stopping the process we're going to query.
        synchronized (sProcessCache) {
            // check the process is still alive/allocated
            if (mProcess != null) {
                // prepare to the write the address to the output buffer.

                // first, conversion to a string containing the hex value.
                String tmp = Long.toString(offset, 16);

                try {
                    // write the address to the buffer
                    mAddressWriter.write(tmp.getBytes());

                    // add CR-LF
                    mAddressWriter.write(sCrLf);

                    // flush it all.
                    mAddressWriter.flush();

                    // read the result. We need to read 2 lines
                    String method = mResultReader.readLine();
                    String source = mResultReader.readLine();

                    // make the backtrace object and return it
                    if (method != null && source != null) {
                        return new NativeStackCallInfo(addr, mLibrary.getLibraryName(), method, source);
                    }
                } catch (IOException e) {
                    // log the error
                    Log.e("ddms",
                            "Error while trying to get information for addr: "
                                    + tmp + " in library: " + mLibrary);
                    // we'll return null later
                }
            }
        }
        return null;
    }
}
