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

import java.util.EventListener;

public interface SpecListener extends EventListener {

    void breakpointSet(SpecEvent e);
    void breakpointDeferred(SpecEvent e);
    void breakpointDeleted(SpecEvent e);
    void breakpointResolved(SpecEvent e);
    void breakpointError(SpecErrorEvent e);

    void watchpointSet(SpecEvent e);
    void watchpointDeferred(SpecEvent e);
    void watchpointDeleted(SpecEvent e);
    void watchpointResolved(SpecEvent e);
    void watchpointError(SpecErrorEvent e);

    void exceptionInterceptSet(SpecEvent e);
    void exceptionInterceptDeferred(SpecEvent e);
    void exceptionInterceptDeleted(SpecEvent e);
    void exceptionInterceptResolved(SpecEvent e);
    void exceptionInterceptError(SpecErrorEvent e);
}
