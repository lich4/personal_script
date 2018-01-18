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

package com.android.ddms;

import com.android.ddmlib.AndroidDebugBridge;
import com.android.ddmlib.DebugPortManager;
import com.android.ddmlib.Log;
import com.android.sdkstats.SdkStatsService;

import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;


/**
 * Start the UI and network.
 */
public class Main {

    public static String sRevision;

    public Main() {
    }

    /*
     * If a thread bails with an uncaught exception, bring the whole
     * thing down.
     */
    private static class UncaughtHandler implements Thread.UncaughtExceptionHandler {
        @Override
        public void uncaughtException(Thread t, Throwable e) {
            Log.e("ddms", "shutting down due to uncaught exception");
            Log.e("ddms", e);
            System.exit(1);
        }
    }
    
    //Added by lichao890427 in 2016.7.21
    static void connectTarget(){
    	try{
    		Process p = Runtime.getRuntime().exec("netstat -an");
    		final BufferedReader inBr = new BufferedReader(new InputStreamReader(p.getInputStream()));  
    		final BufferedReader errBr = new BufferedReader(new InputStreamReader(p.getErrorStream()));
    		final Object lock = new Object();
    		
    		new Thread(new Runnable(){
    			@Override
    			public void run() {
    				try {
    					String lineStr; 
    					while ((lineStr = inBr.readLine()) != null){
    						lineStr = lineStr.toLowerCase();
    						if(-1 != lineStr.indexOf("listening") && -1 != lineStr.indexOf("127.0.0.1:")){
    							int pos = lineStr.indexOf("127.0.0.1:");
    							lineStr = lineStr.substring(pos + 10);
    							lineStr = lineStr.split(" ")[0];
    							Runtime.getRuntime().exec("adb connect 127.0.0.1:" + lineStr);
    						}
    					}
    				} 
    				catch (IOException e) {
    				}
    			}
    		}).start();
    		
    		new Thread(new Runnable(){
    			@Override
    			public void run() {
    				try {
    					String lineStr; 
    					while ((lineStr = errBr.readLine()) != null);
    				} 
    				catch (IOException e) {
    				}
    			}
    		}).start();
    		p.waitFor();
    	}
    	catch(Exception e){
    		
    	}
    }

    /**
     * Parse args, start threads.
     */
    public static void main(String[] args) {
    	connectTarget();
    	
        // In order to have the AWT/SWT bridge work on Leopard, we do this little hack.
        if (isMac()) {
            RuntimeMXBean rt = ManagementFactory.getRuntimeMXBean();
            System.setProperty(
                    "JAVA_STARTED_ON_FIRST_THREAD_" + (rt.getName().split("@"))[0], //$NON-NLS-1$
                    "1"); //$NON-NLS-1$
        }

        Thread.setDefaultUncaughtExceptionHandler(new UncaughtHandler());

        // load prefs and init the default values
        PrefsDialog.init();

        Log.d("ddms", "Initializing");

        // Create an initial shell display with the correct app name.
        Display.setAppName(UIThread.APP_NAME);
        Shell shell = new Shell(Display.getDefault());

        // if this is the first time using ddms or adt, open up the stats service
        // opt out dialog, and request user for permissions.
        SdkStatsService stats = new SdkStatsService();
        stats.checkUserPermissionForPing(shell);

        // the "ping" argument means to check in with the server and exit
        // the application name and version number must also be supplied
        if (args.length >= 3 && args[0].equals("ping")) {
            stats.ping(args);
            return;
        } else if (args.length > 0) {
            Log.e("ddms", "Unknown argument: " + args[0]);
            System.exit(1);
        }

        // get the ddms parent folder location
        String ddmsParentLocation = System.getProperty("com.android.ddms.bindir"); //$NON-NLS-1$

        if (ddmsParentLocation == null) {
            // Tip: for debugging DDMS in eclipse, set this env var to the SDK/tools
            // directory path.
            ddmsParentLocation = System.getenv("com.android.ddms.bindir"); //$NON-NLS-1$
        }

        // we're past the point where ddms can be called just to send a ping, so we can
        // ping for ddms itself.
        ping(stats, ddmsParentLocation);
        stats = null;

        DebugPortManager.setProvider(DebugPortProvider.getInstance());

        // create the three main threads
        UIThread ui = UIThread.getInstance();

        try {
            ui.runUI(ddmsParentLocation);
        } finally {
            PrefsDialog.save();

            AndroidDebugBridge.terminate();
        }

        Log.d("ddms", "Bye");

        // this is kinda bad, but on MacOS the shutdown doesn't seem to finish because of
        // a thread called AWT-Shutdown. This will help while I track this down.
        System.exit(0);
    }

    /** Return true iff we're running on a Mac */
    static boolean isMac() {
        // TODO: Replace usages of this method with
        // org.eclipse.jface.util.Util#isMac() when we switch to Eclipse 3.5
        // (ddms is currently built with SWT 3.4.2 from ANDROID_SWT)
        return System.getProperty("os.name").startsWith("Mac OS"); //$NON-NLS-1$ //$NON-NLS-2$
    }

    private static void ping(SdkStatsService stats, String ddmsParentLocation) {
        Properties p = new Properties();
        try{
            File sourceProp;
            if (ddmsParentLocation != null && ddmsParentLocation.length() > 0) {
                sourceProp = new File(ddmsParentLocation, "source.properties"); //$NON-NLS-1$
            } else {
                sourceProp = new File("source.properties"); //$NON-NLS-1$
            }
            FileInputStream fis = null;
            try {
                fis = new FileInputStream(sourceProp);
                p.load(fis);
            } finally {
                if (fis != null) {
                    try {
                        fis.close();
                    } catch (IOException ignore) {
                    }
                }
            }

            sRevision = p.getProperty("Pkg.Revision"); //$NON-NLS-1$
            if (sRevision != null && sRevision.length() > 0) {
                stats.ping("ddms", sRevision);  //$NON-NLS-1$
            }
        } catch (FileNotFoundException e) {
            // couldn't find the file? don't ping.
        } catch (IOException e) {
            // couldn't find the file? don't ping.
        }
    }
}
