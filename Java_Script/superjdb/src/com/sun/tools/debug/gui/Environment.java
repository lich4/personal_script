/*
 * Copyright (c) 1998, 2011, Oracle and/or its affiliates. All rights reserved.
 * ORACLE PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */

/*
 * This source code is provided to illustrate the usage of a given feature
 * or technique and has been deliberately simplified. Additional steps
 * required for a production-quality application, such as security checks,
 * input validation and proper error handling, might not be present in
 * this sample code.
 */


package com.sun.tools.debug.gui;

import java.io.*;
import com.sun.jdi.*;
import com.sun.tools.debug.bdi.*;

public class Environment {

    private SourceManager sourceManager;
    private ClassManager classManager;
    private ContextManager contextManager;
    private MonitorListModel monitorListModel;
    private ExecutionManager runtime;

    private PrintWriter typeScript;

    private boolean verbose;

    public Environment() {
        this.classManager = new ClassManager(this);
        //### Order of the next three lines is important!  (FIX THIS)
        this.runtime = new ExecutionManager();
        this.sourceManager = new SourceManager(this);
        this.contextManager = new ContextManager(this);
        this.monitorListModel = new MonitorListModel(this);
    }

    // Services used by debugging tools.

    public SourceManager getSourceManager() {
        return sourceManager;
    }

    public ClassManager getClassManager() {
        return classManager;
    }

    public ContextManager getContextManager() {
        return contextManager;
    }

    public MonitorListModel getMonitorListModel() {
        return monitorListModel;
    }

    public ExecutionManager getExecutionManager() {
        return runtime;
    }

    //### TODO:
    //### Tools should attach/detach from environment
    //### via a property, which should call an 'addTool'
    //### method when set to maintain a registry of
    //### tools for exit-time cleanup, etc.  Tool
    //### class constructors should be argument-free, so
    //### that they may be instantiated by bean builders.
    //### Will also need 'removeTool' in case property
    //### value is changed.
    //
    // public void addTool(Tool t);
    // public void removeTool(Tool t);

     public void terminate() {
         System.exit(0);
     }

    // public void refresh();    // notify all tools to refresh their views


    // public void addStatusListener(StatusListener l);
    // public void removeStatusListener(StatusListener l);

    // public void addOutputListener(OutputListener l);
    // public void removeOutputListener(OutputListener l);

    public void setTypeScript(PrintWriter writer) {
        typeScript = writer;
    }

    public void error(String message) {
        if (typeScript != null) {
            typeScript.println(message);
        } else {
            System.out.println(message);
        }
    }

    public void failure(String message) {
        if (typeScript != null) {
            typeScript.println(message);
        } else {
            System.out.println(message);
        }
    }

    public void notice(String message) {
        if (typeScript != null) {
            typeScript.println(message);
        } else {
            System.out.println(message);
        }
    }

    public OutputSink getOutputSink() {
        return new OutputSink(typeScript);
    }

    public void viewSource(String fileName) {
        //### HACK ###
        //### Should use listener here.
        com.sun.tools.debug.gui.GUI.srcTool.showSourceFile(fileName);
    }

    public void viewLocation(Location locn) {
        //### HACK ###
        //### Should use listener here.
        //### Should we use sourceForLocation here?
        com.sun.tools.debug.gui.GUI.srcTool.showSourceForLocation(locn);
    }

    //### Also in 'ContextManager'.  Do we need both?

    public boolean getVerboseFlag() {
        return verbose;
    }

    public void setVerboseFlag(boolean verbose) {
        this.verbose = verbose;
    }

}
