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
import java.util.Vector;
import java.util.List;

//### This is currently just a placeholder!

class JDBMenuBar extends JMenuBar {

    Environment env;

    ExecutionManager runtime;
    ClassManager classManager;
    SourceManager sourceManager;

    CommandInterpreter interpreter;

    JDBMenuBar(Environment env) {
        this.env = env;
        this.runtime = env.getExecutionManager();
        this.classManager = env.getClassManager();
        this.sourceManager = env.getSourceManager();
        this.interpreter = new CommandInterpreter(env, true);

        JMenu fileMenu = new JMenu("File");

        JMenuItem openItem = new JMenuItem("Open...", 'O');
        openItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                openCommand();
            }
        });
        fileMenu.add(openItem);
        addTool(fileMenu, "Exit debugger", "Exit", "exit");

        JMenu cmdMenu = new JMenu("Commands");

        addTool(cmdMenu, "Step into next line", "Step", "step");
        addTool(cmdMenu, "Step over next line", "Next", "next");
        cmdMenu.addSeparator();

        addTool(cmdMenu, "Step into next instruction",
                "Step Instruction", "stepi");
        addTool(cmdMenu, "Step over next instruction",
                "Next Instruction", "nexti");
        cmdMenu.addSeparator();

        addTool(cmdMenu, "Step out of current method call",
                "Step Up", "step up");
        cmdMenu.addSeparator();

        addTool(cmdMenu, "Suspend execution", "Interrupt", "interrupt");
        addTool(cmdMenu, "Continue execution", "Continue", "cont");
        cmdMenu.addSeparator();

        addTool(cmdMenu, "Display current stack", "Where", "where");
        cmdMenu.addSeparator();

        addTool(cmdMenu, "Move up one stack frame", "Up", "up");
        addTool(cmdMenu, "Move down one stack frame", "Down", "down");
        cmdMenu.addSeparator();

        JMenuItem monitorItem = new JMenuItem("Monitor Expression...", 'M');
        monitorItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                monitorCommand();
            }
        });
        cmdMenu.add(monitorItem);

        JMenuItem unmonitorItem = new JMenuItem("Unmonitor Expression...");
        unmonitorItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                unmonitorCommand();
            }
        });
        cmdMenu.add(unmonitorItem);

        JMenu breakpointMenu = new JMenu("Breakpoint");
        JMenuItem stopItem = new JMenuItem("Stop in...", 'S');
        stopItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                buildBreakpoint();
            }
        });
        breakpointMenu.add(stopItem);

        JMenu helpMenu = new JMenu("Help");
        addTool(helpMenu, "Display command list", "Help", "help");

        this.add(fileMenu);
        this.add(cmdMenu);
//      this.add(breakpointMenu);
        this.add(helpMenu);
    }

    private void buildBreakpoint() {
        Frame frame = JOptionPane.getRootFrame();
        JDialog dialog = new JDialog(frame, "Specify Breakpoint");
        Container contents = dialog.getContentPane();
        Vector<String> classes = new Vector<String>();
        classes.add("Foo");
        classes.add("Bar");
        JList list = new JList(classes);
        JScrollPane scrollPane = new JScrollPane(list);
        contents.add(scrollPane);
        dialog.show();

    }

    private void monitorCommand() {
        String expr = (String)JOptionPane.showInputDialog(null,
                           "Expression to monitor:", "Add Monitor",
                           JOptionPane.QUESTION_MESSAGE, null, null, null);
        if (expr != null) {
            interpreter.executeCommand("monitor " + expr);
        }
    }

    private void unmonitorCommand() {
        List monitors = env.getMonitorListModel().monitors();
        String expr = (String)JOptionPane.showInputDialog(null,
                           "Expression to unmonitor:", "Remove Monitor",
                           JOptionPane.QUESTION_MESSAGE, null,
                           monitors.toArray(),
                           monitors.get(monitors.size()-1));
        if (expr != null) {
            interpreter.executeCommand("unmonitor " + expr);
        }
    }

    private void openCommand() {
        JFileChooser chooser = new JFileChooser();
        JDBFileFilter filter = new JDBFileFilter("java", "Java source code");
        chooser.setFileFilter(filter);
        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            System.out.println("Chose file: " + chooser.getSelectedFile().getName());
        }
    }

    private void addTool(JMenu menu, String toolTip, String labelText,
                         String command) {
        JMenuItem mi = new JMenuItem(labelText);
        mi.setToolTipText(toolTip);
        final String cmd = command;
        mi.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                interpreter.executeCommand(cmd);
            }
        });
        menu.add(mi);
    }

}
