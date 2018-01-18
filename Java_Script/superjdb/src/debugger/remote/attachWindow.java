package debugger.remote;

import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;

import javax.swing.BoxLayout;
import javax.swing.JFrame;
import javax.swing.JTree;

public class attachWindow extends JFrame{
	private JTree processTree;
	
	public attachWindow() {
		getContentPane().addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent arg0) {
				processTree.setSize(getContentPane().getWidth(), getContentPane().getHeight());
			}
		});
		getContentPane().setLayout(new BoxLayout(getContentPane(), BoxLayout.X_AXIS));
		
		processTree = new JTree();
		getContentPane().add(processTree);
		
		setSize(300, 300);
	}

}
