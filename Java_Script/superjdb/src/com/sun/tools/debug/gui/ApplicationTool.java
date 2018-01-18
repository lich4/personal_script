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

import javax.swing.*;

import com.sun.tools.debug.bdi.*;

import java.awt.*;
import java.awt.event.*;

public class ApplicationTool extends JPanel {

    private static final long serialVersionUID = 310966063293205714L;

    private ExecutionManager runtime;

    private TypeScript script;

    private static final String PROMPT = "Input:";

    public ApplicationTool(Environment env) {

        super(new BorderLayout());

        this.runtime = env.getExecutionManager();

        this.script = new TypeScript(PROMPT, false); // No implicit echo.
        this.add(script);

        script.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                runtime.sendLineToApplication(script.readln());
            }
        });

        runtime.addApplicationEchoListener(new TypeScriptOutputListener(script));
        runtime.addApplicationOutputListener(new TypeScriptOutputListener(script));
        runtime.addApplicationErrorListener(new TypeScriptOutputListener(script));

        //### should clean up on exit!

    }

    /******
    public void setFont(Font f) {
        script.setFont(f);
    }
    ******/

}
