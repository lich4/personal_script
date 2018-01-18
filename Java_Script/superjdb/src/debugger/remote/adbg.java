package debugger.remote;

import java.awt.Font;
import java.awt.Insets;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.StringTokenizer;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import com.sun.jdi.ClassType;
import com.sun.jdi.InterfaceType;
import com.sun.jdi.ReferenceType;
import com.sun.tools.debug.tty.Env;
import com.sun.tools.debug.tty.MessageOutput;
import com.sun.tools.debug.tty.TTY;
import com.sun.tools.debug.tty.VMConnection;
import com.sun.tools.jdi.ClassTypeImpl;

public class adbg {
	
	private static mainWindow frame;
	private static VMConnection con;
	private static TTY tty;
	private static boolean connected;
	private static long extrabit;
	
	public static long canWatchFieldModification = 0x1;
	public static long canWatchFieldAccess = 0x2;
	public static long canGetBytecodes = 0x4;
	public static long canGetSyntheticAttribute = 0x8;
	public static long canGetOwnedMonitorInfo = 0x10;
	public static long canGetCurrentContendedMonitor = 0x20;
	public static long canGetMonitorInfo = 0x40;
	public static long canUseInstanceFilters = 0x80;
	public static long canRedefineClasses = 0x100;
	public static long canAddMethod = 0x200;
	public static long canUnrestrictedlyRedefineClasses = 0x400;
	public static long canPopFrames = 0x800;
	public static long canGetSourceDebugExtension = 0x1000;
	public static long canRequestVMDeathEvent = 0x2000;
	public static long canGetMethodReturnValues = 0x4000;
	public static long canGetInstanceInfo = 0x8000;
	public static long canUseSourceNameFilters = 0x10000;
	public static long canForceEarlyReturn = 0x20000;
	public static long canBeModified = 0x40000;
	public static long canRequestMonitorEvents = 0x80000;
	public static long canGetMonitorFrameInfo = 0x100000;
	public static long canGetClassFileVersion = 0x200000;
	public static long canGetConstantPool = 0x400000;
	
	public static void init(){
		MessageOutput.textResources = ResourceBundle.getBundle
	            ("com.sun.tools.debug.tty.TTYResources",
	             Locale.getDefault());
		
        frame = new mainWindow();  
        frame.setSize(800,600);  
        frame.setVisible(true); 
        
        connected = false;
        extrabit = 0;
	}
	
	public static void main(String[] args){
		init();
	}
	
	public static void getExtra(){
		if(extrabit == 0 && con != null && con.vm != null){
			if(con.vm.canAddMethod())
				extrabit |= canAddMethod;
			if(con.vm.canBeModified())
				extrabit |= canBeModified;
			if(con.vm.canForceEarlyReturn())
				extrabit |= canForceEarlyReturn;
			if(con.vm.canGetBytecodes())
				extrabit |= canGetBytecodes;
			if(con.vm.canGetClassFileVersion())
				extrabit |= canGetClassFileVersion;
			if(con.vm.canGetConstantPool())
				extrabit |= canGetConstantPool;
			if(con.vm.canGetCurrentContendedMonitor())
				extrabit |= canGetCurrentContendedMonitor;
			if(con.vm.canGetInstanceInfo())
				extrabit |= canGetInstanceInfo;
			if(con.vm.canGetMethodReturnValues())
				extrabit |= canGetMethodReturnValues;
			if(con.vm.canGetMonitorFrameInfo())
				extrabit |= canGetMonitorFrameInfo;
			if(con.vm.canGetMonitorInfo())
				extrabit |= canGetMonitorInfo;
			if(con.vm.canGetOwnedMonitorInfo())
				extrabit |= canGetOwnedMonitorInfo;
			if(con.vm.canGetSourceDebugExtension())
				extrabit |= canGetSourceDebugExtension;
			if(con.vm.canGetSyntheticAttribute())
				extrabit |= canGetSyntheticAttribute;
			if(con.vm.canPopFrames())
				extrabit |= canPopFrames;
			if(con.vm.canRedefineClasses())
				extrabit |= canRedefineClasses;
			if(con.vm.canRequestMonitorEvents())
				extrabit |= canRequestMonitorEvents;
			if(con.vm.canRequestVMDeathEvent())
				extrabit |= canRequestVMDeathEvent;
			if(con.vm.canUnrestrictedlyRedefineClasses())
				extrabit |= canUnrestrictedlyRedefineClasses;
			if(con.vm.canUseInstanceFilters())
				extrabit |= canUseInstanceFilters;
			if(con.vm.canUseSourceNameFilters())
				extrabit |= canUseSourceNameFilters;
			if(con.vm.canWatchFieldModification())
				extrabit |= canWatchFieldModification;
			if(con.vm.canWatchFieldAccess())
				extrabit |= canWatchFieldAccess;
		}
	}
	
	public static void execJdbCommand(String cmd){
		if(con == null || con.vm == null){
			System.out.println("jdb not connectet!");
			return;
		}
			
	    StringTokenizer t = new StringTokenizer(cmd);
	    if(tty != null){
		    if (t.hasMoreTokens()) {
		        tty.executeCommand(t);
		    }
	    }
	}
	
	public static void execSysCommandInner(String command) throws InterruptedException, IOException{
		Process p = Runtime.getRuntime().exec(command);
		final BufferedReader inBr = new BufferedReader(new InputStreamReader(p.getInputStream()));  
		final BufferedReader errBr = new BufferedReader(new InputStreamReader(p.getErrorStream()));
		final Object lock = new Object();
		
		new Thread(new Runnable(){
			@Override
			public void run() {
				try {
					String lineStr; 
					while ((lineStr = inBr.readLine()) != null)  
						synchronized(lock){
							System.out.println(lineStr);
						}
				} 
				catch (IOException e) {
				}
			}
		}).start();
		
		new Thread(new Runnable(){
			@Override
			public void run() {
				try {
					String lineStr; 
					while ((lineStr = errBr.readLine()) != null)  
						synchronized(lock){
							System.out.println(lineStr);
						}
				} 
				catch (IOException e) {
				}
			}
		}).start();

		p.waitFor();
	}
	
	public static void execSysCommand(String command){
		String os = System.getProperty("os.name").toLowerCase();
		String bash = "";
		String output = "";
		
		try{
			execSysCommandInner(command);
		}
		catch (IOException e) {
			try{
				execSysCommandInner("cmd /c " + command);
			}
			catch(Exception e1){
				
			}
		} 
		catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	
	public static void onConnect(){
		try {
			consoleText.setTypeJdb();
			tty = new TTY();
			con.vm.suspend();//suspend on time
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void onOpen(){
		try{
			Env.init("com.sun.jdi.CommandLineLaunch:main=test.test,options=-classpath e:\\test,", true, 0);
			con = Env.connection();
			if(con == null || con.vm == null){
				connected = false;
				return;
			}
			connected = true;
			onConnect();
		}
		catch(Exception e){
			connected = false;
			return;
		}
	}
	
	public static void onAttach(){
		try{
			Env.init("com.sun.jdi.SocketAttach:hostname=localhost,port=8606,", false, 0);
			con = Env.connection();
			if(con == null || con.vm == null){
				connected = false;
				return;
			}
			connected = true;
			onConnect();
		}
		catch(Exception e){
			connected = false;
			return;
		}
	}
	
	public static void onSetting(){
		new settingWindow().setVisible(true);
	}
	
	
	
	public static String getBooleanStr(long bit){
		if(bit != 0)
			return "true";
		else
			return "false";
	}
	
	public static void onTargetInfo(){
		String info = "";
		if(con != null && con.vm != null){
			info += "------------------------------Description----------------------------\r\n";
			info += con.vm.description() + "\r\n";
			info += "------------------------------Version--------------------------------\r\n";
			info += con.vm.version() + "\r\n";
			info += "------------------------------Name-----------------------------------\r\n";
			info += con.vm.name() + "\r\n";
			
			if(extrabit == 0)
				getExtra();
			info += "------------------------------Extra----------------------------------\r\n";					
			info += "\tcanWatchFieldModification:" + getBooleanStr(extrabit&canWatchFieldModification) + "\r\n";
			info += "\tcanWatchFieldAccess:" + getBooleanStr(extrabit&canWatchFieldAccess) + "\r\n";
			info += "\tcanGetBytecodes:" + getBooleanStr(extrabit&canGetBytecodes) + "\r\n";
			info += "\tcanGetSyntheticAttribute:" + getBooleanStr(extrabit&canGetSyntheticAttribute) + "\r\n";
			info += "\tcanGetOwnedMonitorInfo:" + getBooleanStr(extrabit&canGetOwnedMonitorInfo) + "\r\n";
			info += "\tcanGetCurrentContendedMonitor:" + getBooleanStr(extrabit&canGetCurrentContendedMonitor) + "\r\n";
			info += "\tcanGetMonitorInfo:" + getBooleanStr(extrabit&canGetMonitorInfo) + "\r\n";
			info += "\tcanUseInstanceFilters:" + getBooleanStr(extrabit&canUseInstanceFilters) + "\r\n";
			info += "\tcanRedefineClasses:" + getBooleanStr(extrabit&canRedefineClasses) + "\r\n";
			info += "\tcanAddMethod:" + getBooleanStr(extrabit&canAddMethod) + "\r\n";
			info += "\tcanUnrestrictedlyRedefineClasses:" + getBooleanStr(extrabit&canUnrestrictedlyRedefineClasses) + "\r\n";
			info += "\tcanPopFrames:" + getBooleanStr(extrabit&canPopFrames) + "\r\n";
			info += "\tcanGetSourceDebugExtension:" + getBooleanStr(extrabit&canGetSourceDebugExtension) + "\r\n";
			info += "\tcanRequestVMDeathEvent:" + getBooleanStr(extrabit&canRequestVMDeathEvent) + "\r\n";
			info += "\tcanGetMethodReturnValues:" + getBooleanStr(extrabit&canGetMethodReturnValues) + "\r\n";
			info += "\tcanGetInstanceInfo:" + getBooleanStr(extrabit&canGetInstanceInfo) + "\r\n";
			info += "\tcanUseSourceNameFilters:" + getBooleanStr(extrabit&canUseSourceNameFilters) + "\r\n";
			info += "\tcanForceEarlyReturn:" + getBooleanStr(extrabit&canForceEarlyReturn) + "\r\n";
			info += "\tcanBeModified:" + getBooleanStr(extrabit&canBeModified) + "\r\n";
			info += "\tcanRequestMonitorEvents:" + getBooleanStr(extrabit&canRequestMonitorEvents) + "\r\n";
			info += "\tcanGetMonitorFrameInfo:" + getBooleanStr(extrabit&canGetMonitorFrameInfo) + "\r\n";
			info += "\tcanGetClassFileVersion:" + getBooleanStr(extrabit&canGetClassFileVersion) + "\r\n";
			info += "\tcanGetConstantPool:" + getBooleanStr(extrabit&canGetConstantPool) + "\r\n";
		}
		
		JFrame panel = new JFrame();
		JTextArea ta = new JTextArea(info);
		ta.setMargin(new Insets(20, 20, 20, 20));
		JScrollPane scroll = new JScrollPane(ta);
		ta.setFont(new Font("΢���ź�", Font.PLAIN, 16));
		panel.add(scroll);
		panel.setTitle("Vm Information");
		panel.setLocation(200, 200);
		panel.setSize(600, 600);
		scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		panel.setVisible(true);
	}
	
	public static void onShowClasses(){
		new classWindow().setVisible(true);
	}
	
	public static List<ReferenceType> getAllClasses(){
		if(con == null || con.vm == null){
			return new ArrayList();
		}
		return Env.vm().allClasses();
	}
}
