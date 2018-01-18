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


package com.sun.tools.debug.bdi;

import com.sun.jdi.VirtualMachine;
import com.sun.jdi.VMDisconnectedException;

/**
 * Our repository of what we know about the state of one
 * running VM.
 */
class Session {

    final VirtualMachine vm;
    final ExecutionManager runtime;
    final OutputListener diagnostics;

    boolean running = true;  // Set false by JDIEventSource
    boolean interrupted = false;  // Set false by JDIEventSource

    private JDIEventSource eventSourceThread = null;
    private int traceFlags;
    private boolean dead = false;

    public Session(VirtualMachine vm, ExecutionManager runtime,
                   OutputListener diagnostics) {
        this.vm = vm;
        this.runtime = runtime;
        this.diagnostics = diagnostics;
        this.traceFlags = VirtualMachine.TRACE_NONE;
    }

    /**
     * Determine if VM is interrupted, i.e, present and not running.
     */
    public boolean isInterrupted() {
        return interrupted;
    }

    public void setTraceMode(int traceFlags) {
        this.traceFlags = traceFlags;
        if (!dead) {
            vm.setDebugTraceMode(traceFlags);
        }
    }

    public boolean attach() {
        vm.setDebugTraceMode(traceFlags);
        diagnostics.putString("Connected to VM");
        eventSourceThread = new JDIEventSource(this);
        eventSourceThread.start();
        return true;
    }

    public void detach() {
        if (!dead) {
            eventSourceThread.interrupt();
            eventSourceThread = null;
            //### The VM may already be disconnected
            //### if the debuggee did a System.exit().
            //### Exception handler here is a kludge,
            //### Rather, there are many other places
            //### where we need to handle this exception,
            //### and initiate a detach due to an error
            //### condition, e.g., connection failure.
            try {
                vm.dispose();
            } catch (VMDisconnectedException ee) {}
            dead = true;
            diagnostics.putString("Disconnected from VM");
        }
    }
}
