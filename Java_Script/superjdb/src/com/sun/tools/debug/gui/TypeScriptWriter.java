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

public class TypeScriptWriter extends Writer {

    TypeScript script;

    public TypeScriptWriter(TypeScript script) {
        this.script = script;
    }

    @Override
    public void write(char[] cbuf, int off, int len) throws IOException {
        script.append(String.valueOf(cbuf, off, len));
    }

    @Override
    public void flush() {
        script.flush();
    }

    @Override
    public void close() {
        script.flush();
    }
}
