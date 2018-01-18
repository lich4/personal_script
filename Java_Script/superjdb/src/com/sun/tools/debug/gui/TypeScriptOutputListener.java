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

import com.sun.tools.debug.bdi.OutputListener;

public class TypeScriptOutputListener implements OutputListener {

    private TypeScript script;
    private boolean appendNewline;

    public TypeScriptOutputListener(TypeScript script) {
        this(script, false);
    }

    public TypeScriptOutputListener(TypeScript script, boolean appendNewline) {
        this.script = script;
        this.appendNewline = appendNewline;
    }

    @Override
    public void putString(String s) {
        script.append(s);
        if (appendNewline) {
            script.newline();
    }
    }

}
