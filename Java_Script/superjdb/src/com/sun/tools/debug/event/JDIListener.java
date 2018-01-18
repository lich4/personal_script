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


package com.sun.tools.debug.event;

import java.util.EventListener;

public interface JDIListener extends EventListener {
    void accessWatchpoint(AccessWatchpointEventSet e);
    void classPrepare(ClassPrepareEventSet e);
    void classUnload(ClassUnloadEventSet e);
    void exception(ExceptionEventSet e);
    void locationTrigger(LocationTriggerEventSet e);
    void modificationWatchpoint(ModificationWatchpointEventSet e);
    void threadDeath(ThreadDeathEventSet e);
    void threadStart(ThreadStartEventSet e);
    void vmDeath(VMDeathEventSet e);
    void vmDisconnect(VMDisconnectEventSet e);
    void vmStart(VMStartEventSet e);
}
