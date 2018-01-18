/*
 * Copyright (c) 1999, 2011, Oracle and/or its affiliates. All rights reserved.
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

public abstract class BreakpointSpec extends EventRequestSpec {

    BreakpointSpec(EventRequestSpecList specs, ReferenceTypeSpec refSpec) {
        super(specs, refSpec);
    }

    @Override
    void notifySet(SpecListener listener, SpecEvent evt) {
        listener.breakpointSet(evt);
    }

    @Override
    void notifyDeferred(SpecListener listener, SpecEvent evt) {
        listener.breakpointDeferred(evt);
    }

    @Override
    void notifyResolved(SpecListener listener, SpecEvent evt) {
        listener.breakpointResolved(evt);
    }

    @Override
    void notifyDeleted(SpecListener listener, SpecEvent evt) {
        listener.breakpointDeleted(evt);
    }

    @Override
    void notifyError(SpecListener listener, SpecErrorEvent evt) {
        listener.breakpointError(evt);
    }
}
