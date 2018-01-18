package debugger.remote;

import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.StringTokenizer;

import javax.swing.JTextArea;

public class consoleText extends JTextArea{
	private static int Type = 0;//0:system command	1:jdb command
	private static String Tag = "Jdb>";
	
	private final class jdbAdapter extends KeyAdapter {
		@Override
		public void keyPressed(KeyEvent paramKeyEvent) {
			if(paramKeyEvent.getKeyCode() == KeyEvent.VK_ENTER){
				String[] splitter = consoleText.this.getText().split("\r\n");
				String cmd;
				if(splitter.length > 0)
					cmd = splitter[splitter.length - 1];
				else
					cmd = consoleText.this.getText();
				cmd = cmd.replace(Tag, "").replace("\r","").replace("\n", "");
				if(Type == 0)
					adbg.execSysCommand(cmd);
				else if(Type == 1)
					adbg.execJdbCommand(cmd);
			}
		}
	}

	private ByteArrayOutputStream bout;
	private PrintStream ps;
	
	public consoleText() {
		bout=new ByteArrayOutputStream();
		ps = new PrintStream(bout);
		
		System.setErr(ps);
		System.setOut(ps);	
		addKeyListener(new jdbAdapter());
		new Thread(new Runnable(){
			@Override
			public void run() {
				while(true){
					try {
						if(bout.size() > 1){
							consoleText.this.setText(consoleText.this.getText() + new String(bout.toByteArray()) + "\r\n" + Tag);
							bout.reset();
							consoleText.this.setCaretPosition(consoleText.this.getDocument().getLength());
						}
						Thread.sleep(1000);
					} 
					catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			}
		}).start();
		
		setLineWrap(true);
		System.out.print("\r\n" + Tag);
	} 
	
	public static void setTypeCmd(){
		Type = 0;
		Tag = "Cmd>";
	}
	
	public static void setTypeJdb(){
		Type = 1;
		Tag = "Jdb>";
	}
}
