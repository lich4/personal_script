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

import java.awt.event.*;

class JDBToolBar extends JToolBar {

    Environment env;

    ExecutionManager runtime;
    ClassManager classManager;
    SourceManager sourceManager;

    CommandInterpreter interpreter;

    JDBToolBar(Environment env) {

        this.env = env;
        this.runtime = env.getExecutionManager();
        this.classManager = env.getClassManager();
        this.sourceManager = env.getSourceManager();
        this.interpreter = new CommandInterpreter(env, true);

        //===== Configure toolbar here =====

        addTool("Run application", "run", "run");
        addTool("Connect to application", "connect", "connect");
        addSeparator();

        addTool("Step into next line", "step", "step");
        addTool("Step over next line", "next", "next");
//      addSeparator();

//      addTool("Step into next instruction", "stepi", "stepi");
//      addTool("Step over next instruction", "nexti", "nexti");
//      addSeparator();

        addTool("Step out of current method call", "step up", "step up");
        addSeparator();

        addTool("Suspend execution", "interrupt", "interrupt");
        addTool("Continue execution", "cont", "cont");
        addSeparator();

//      addTool("Display current stack", "where", "where");
//      addSeparator();

        addTool("Move up one stack frame", "up", "up");
        addTool("Move down one stack frame", "down", "down");
//      addSeparator();

//      addTool("Display command list", "help", "help");
//      addSeparator();

//      addTool("Exit debugger", "exit", "exit");

        //==================================

    }

    private void addTool(String toolTip, String labelText, String command) {
        JButton button = new JButton(labelText);
        button.setToolTipText(toolTip);
        final String cmd = command;
        button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                interpreter.executeCommand(cmd);
            }
        });
        this.add(button);
    }

}
