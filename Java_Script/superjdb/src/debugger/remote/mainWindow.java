package debugger.remote;

import javax.swing.JFrame;
import javax.swing.JMenuBar;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.JTextPane;

import com.sun.tools.debug.tty.Env;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.Insets;
import java.awt.Rectangle;

import javax.swing.SwingConstants;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.GridLayout;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import javax.swing.JRadioButtonMenuItem;

public class mainWindow extends JFrame{

	public mainWindow() {
		
		JMenuBar menuBar = new JMenuBar();
		setJMenuBar(menuBar);

		JMenu mnFile = new JMenu("File\t");
		mnFile.setFont(new Font("΢���ź�", Font.PLAIN, 25));
		menuBar.add(mnFile);
		
		JMenuItem mntmOpen = new JMenuItem("Open");
		mntmOpen.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				adbg.onOpen();
			}
		});
		mntmOpen.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnFile.add(mntmOpen);
		
		JMenuItem mntmAttachToVm = new JMenuItem("Attach To Vm");
		mntmAttachToVm.setFont(new Font("Dialog", Font.PLAIN, 18));
		mntmAttachToVm.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				adbg.onAttach();
			}
		});
		mnFile.add(mntmAttachToVm);
		
		JMenuItem mntmSettings = new JMenuItem("Settings");
		mntmSettings.setFont(new Font("Dialog", Font.PLAIN, 18));
		mntmSettings.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				adbg.onSetting();
			}
		});
		mnFile.add(mntmSettings);
		
		JMenuItem menuItem = new JMenuItem("------------------");
		mnFile.add(menuItem);
		
		JMenuItem mntmExit = new JMenuItem("Exit");
		mntmExit.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnFile.add(mntmExit);
		
		JMenu mnView = new JMenu("View\t");
		mnView.setFont(new Font("΢���ź�", Font.PLAIN, 25));
		menuBar.add(mnView);
		
		JMenuItem mntmProcess = new JMenuItem("Process");
		mntmProcess.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnView.add(mntmProcess);
		
		JMenu mnCommand = new JMenu("Command");
		mnCommand.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnView.add(mnCommand);
		
		JRadioButtonMenuItem rdbtnmntmSystemCommand = new JRadioButtonMenuItem("System Command");
		rdbtnmntmSystemCommand.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent paramActionEvent) {
				consoleText.setTypeCmd();
			}
		});
		rdbtnmntmSystemCommand.setSelected(true);
		rdbtnmntmSystemCommand.setFont(new Font("Dialog", Font.PLAIN, 15));
		mnCommand.add(rdbtnmntmSystemCommand);
		
		JRadioButtonMenuItem rdbtnmntmJdbCommand = new JRadioButtonMenuItem("Jdb Command");
		rdbtnmntmJdbCommand.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent paramActionEvent) {
				consoleText.setTypeJdb();
			}
		});
		mnCommand.add(rdbtnmntmJdbCommand);
		
		JMenuItem menuItem_1 = new JMenuItem("------------------");
		mnView.add(menuItem_1);
		
		JMenuItem mntmClassinfo = new JMenuItem("ClassInfo");
		mntmClassinfo.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent paramActionEvent) {
				adbg.onShowClasses();
			}
		});
		mntmClassinfo.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnView.add(mntmClassinfo);
		
		JMenuItem mntmThread = new JMenuItem("Thread");
		mntmThread.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnView.add(mntmThread);
		
		JMenuItem mntmThreadgroup = new JMenuItem("ThreadGroup");
		mntmThreadgroup.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnView.add(mntmThreadgroup);
		
		JMenuItem mntmEvent = new JMenuItem("Event");
		mntmEvent.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnView.add(mntmEvent);
		
		JMenuItem mntmTargetinfo = new JMenuItem("TargetInfo");
		mntmTargetinfo.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				adbg.onTargetInfo();
			}
		});
		mntmTargetinfo.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnView.add(mntmTargetinfo);
		
		JMenuItem mntmSourcecode = new JMenuItem("SourceCode");
		mntmSourcecode.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnView.add(mntmSourcecode);
		
		JMenuItem mntmExpression = new JMenuItem("Expression");
		mntmExpression.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnView.add(mntmExpression);
		
		JMenuItem mntmLocals = new JMenuItem("Locals");
		mntmLocals.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnView.add(mntmLocals);
		
		JMenuItem mntmBreakpoints = new JMenuItem("BreakPoints");
		mntmBreakpoints.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnView.add(mntmBreakpoints);
		
		JMenuItem mntmCallstack = new JMenuItem("CallStack");
		mntmCallstack.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnView.add(mntmCallstack);
		
		JMenuItem menuItem_2 = new JMenuItem("------------------");
		mnView.add(menuItem_2);
		
		JMenuItem mntmOpcode = new JMenuItem("OpCode");
		mntmOpcode.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnView.add(mntmOpcode);
		
		JMenuItem mntmRedefineclass = new JMenuItem("RedefineClass");
		mntmRedefineclass.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnView.add(mntmRedefineclass);
		
		JMenu mnDebug = new JMenu("Debug\t");
		mnDebug.setFont(new Font("΢���ź�", Font.PLAIN, 25));
		menuBar.add(mnDebug);
		
		JMenuItem mntmResume = new JMenuItem("Resume");
		mntmResume.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnDebug.add(mntmResume);
		
		JMenuItem mntmSuspend = new JMenuItem("Suspend");
		mntmSuspend.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnDebug.add(mntmSuspend);
		
		JMenuItem mntmTerminate = new JMenuItem("Terminate");
		mntmTerminate.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnDebug.add(mntmTerminate);
		
		JMenuItem mntmDisconnect = new JMenuItem("Disconnect");
		mntmDisconnect.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnDebug.add(mntmDisconnect);
		
		JMenuItem mntmStepinto = new JMenuItem("StepInto");
		mntmStepinto.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnDebug.add(mntmStepinto);
		
		JMenuItem mntmStepintoins = new JMenuItem("StepIntoIns");
		mntmStepintoins.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnDebug.add(mntmStepintoins);
		
		JMenuItem mntmStepover = new JMenuItem("StepOver");
		mntmStepover.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnDebug.add(mntmStepover);
		
		JMenuItem mntmTrace = new JMenuItem("Trace");
		mntmTrace.setFont(new Font("Dialog", Font.PLAIN, 18));
		mnDebug.add(mntmTrace);
		
		JMenu mnHelp = new JMenu("Help\t");
		mnHelp.setFont(new Font("΢���ź�", Font.PLAIN, 25));
		menuBar.add(mnHelp);
		
		//getContentPane().setLayout(new GridLayout(1, 2, 0, 0));
		
		JTextArea textArea = new consoleText();
		textArea.setMargin(new Insets(20, 20, 20, 20));
		JScrollPane scrollPane = new JScrollPane(textArea);
		scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
		getContentPane().add(scrollPane);

		
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		this.setLocation(500,300);
	}

}
