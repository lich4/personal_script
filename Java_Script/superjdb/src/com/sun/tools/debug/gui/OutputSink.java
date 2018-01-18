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

// This class is used in 'CommandInterpreter' as a hook to
// allow messagebox style command output as an alternative
// to a typescript. It should be an interface, not a class.

public class OutputSink extends PrintWriter {

    // Currently, we do no buffering,
    // so 'show' is a no-op.

    OutputSink(Writer writer) {
        super(writer);
    }

    public void show() {
        // ignore
    }
}
