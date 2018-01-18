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

public class ClassManager {

    // This class is provided primarily for symmetry with
    // SourceManager.  Currently, it does very little.
    // If we add facilities in the future that require that
    // class files be read outside of the VM, for example, to
    // provide a disassembled view of a class for bytecode-level
    // debugging, the required class file management will be done
    // here.

    private SearchPath classPath;

    public ClassManager(Environment env) {
        this.classPath = new SearchPath("");
    }

    public ClassManager(SearchPath classPath) {
        this.classPath = classPath;
    }

    /*
     * Set path for access to class files.
     */

    public void setClassPath(SearchPath sp) {
        classPath = sp;
    }

    /*
     * Get path for access to class files.
     */

    public SearchPath getClassPath() {
        return classPath;
    }

}
