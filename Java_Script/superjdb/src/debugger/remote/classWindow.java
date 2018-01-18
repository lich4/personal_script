package debugger.remote;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;

import com.sun.jdi.Field;
import com.sun.jdi.InterfaceType;
import com.sun.jdi.Location;
import com.sun.jdi.Method;
import com.sun.jdi.ObjectReference;
import com.sun.jdi.ReferenceType;
import com.sun.tools.debug.tty.Env;
import com.sun.tools.jdi.ClassTypeImpl;
import com.sun.tools.jdi.FieldImpl;
import com.sun.tools.jdi.InterfaceTypeImpl;
import com.sun.tools.jdi.ReferenceTypeImpl;

import java.awt.BorderLayout;
import java.util.HashMap;
import java.util.List;
import javax.swing.event.TreeExpansionListener;
import javax.swing.event.TreeExpansionEvent;
import java.awt.event.MouseAdapter;

public class classWindow extends JFrame{
	private JTree classTree;
	private DefaultMutableTreeNode root;
	
	public classWindow() {
		getContentPane().addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(java.awt.event.MouseEvent paramMouseEvent) {
				if(classTree.getSelectionPath() == null || classTree.getSelectionPath().getLastPathComponent() == null)
					return;
				DefaultMutableTreeNode node = (DefaultMutableTreeNode)classTree.getSelectionPath().getLastPathComponent();
				Object userobject = node.getUserObject();

				if(userobject instanceof ClassTypeImpl){
					if(node.getChildCount() == 0){
						ClassTypeImpl curcls = (ClassTypeImpl)userobject;
						if(!curcls.genericSignature().equals(""))
							node.add(new DefaultMutableTreeNode("Signature:" + curcls.genericSignature()));
						if(curcls.classLoader() != null)
							node.add(new DefaultMutableTreeNode("ClassLoader:" + curcls.classLoader().toString()));
						if(curcls.superclass() != null)
							node.add(new DefaultMutableTreeNode("SuperClass:" + curcls.superclass().name()));
						node.add(new DefaultMutableTreeNode("MajorVersion:" + curcls.majorVersion() + " MinorVersion:" + curcls.majorVersion()));
						node.add(new DefaultMutableTreeNode("ConstantPoolCount:" + curcls.constantPoolCount()));
						
						String attribute = "Attribute:";
						if(curcls.isAbstract())
							attribute += "abstract ";
						if(curcls.isEnum())
							attribute += "enum";
						if(curcls.isFinal())
							attribute += "final";
						if(curcls.isPrivate())
							attribute += "private";
						if(curcls.isProtected())
							attribute += "protected";
						if(curcls.isPublic())
							attribute += "public";
						if(curcls.isStatic())
							attribute += "static";
						if(curcls.isVerified())
							attribute += "verified";
						if(curcls.isInitialized())
							attribute += "initialized";
						if(curcls.isPackagePrivate())
							attribute += "packageprivate";
						if(curcls.isPrepared())
							attribute += "prepared";
						node.add(new DefaultMutableTreeNode(attribute));
						
						try{
							if(curcls.sourceName() != null)
								node.add(new DefaultMutableTreeNode("SourceName:" + curcls.sourceName()));
							if(curcls.sourceDebugExtension() != null)
								node.add(new DefaultMutableTreeNode("SourceDbgExt:" + curcls.sourceDebugExtension()));					
						}
						catch(Exception e){
							
						}
						
						DefaultMutableTreeNode interfacenode = new DefaultMutableTreeNode("Interfaces");
						node.add(interfacenode);
						for(ReferenceType refType:curcls.allInterfaces()){
							DefaultMutableTreeNode curnode = new DefaultMutableTreeNode(refType.name());
							curnode.setUserObject(refType);
							interfacenode.add(curnode);//可展开
						}
						
						DefaultMutableTreeNode subclassnode = new DefaultMutableTreeNode("SubClasses");
						node.add(subclassnode);
						for(ReferenceType refType:curcls.subclasses()){
							DefaultMutableTreeNode curnode = new DefaultMutableTreeNode(refType.name());
							curnode.setUserObject(refType);
							subclassnode.add(curnode);//可展开
						}
						
						DefaultMutableTreeNode fieldnode = new DefaultMutableTreeNode("Fields");
						node.add(fieldnode);
						for(Field refType:curcls.allFields()){
							DefaultMutableTreeNode curnode = new DefaultMutableTreeNode(refType.name());
							curnode.setUserObject(refType);
							fieldnode.add(curnode);//可展开
						}

						DefaultMutableTreeNode methodnode = new DefaultMutableTreeNode("Methods");
						node.add(methodnode);
						for(Method refType:curcls.allMethods()){
							DefaultMutableTreeNode curnode = new DefaultMutableTreeNode(refType.name());
							curnode.setUserObject(refType);
							methodnode.add(curnode);//可展开
						}						
						
						DefaultMutableTreeNode nestedtypenode = new DefaultMutableTreeNode("NestedTypes");
						node.add(nestedtypenode);
						for(ReferenceType refType:curcls.nestedTypes()){
							DefaultMutableTreeNode curnode = new DefaultMutableTreeNode(refType.name());
							nestedtypenode.add(curnode);
						}	
						
						try{
							DefaultMutableTreeNode linelocnode = new DefaultMutableTreeNode("LineLocations");
							node.add(linelocnode);
							for(Location refType:curcls.allLineLocations()){
								DefaultMutableTreeNode curnode = new DefaultMutableTreeNode("" + refType.lineNumber());
								linelocnode.add(curnode);
							}		
						}
						catch(Exception e){
							
						}
						
						DefaultMutableTreeNode stratanode = new DefaultMutableTreeNode("Stratas");
						node.add(stratanode);
						for(String refType:curcls.availableStrata()){
							DefaultMutableTreeNode curnode = new DefaultMutableTreeNode(refType);
							stratanode.add(curnode);
						}	
						
						DefaultMutableTreeNode instancenode = new DefaultMutableTreeNode("Instances");
						node.add(instancenode);
						for(ObjectReference refType:curcls.instances(65536)){
							DefaultMutableTreeNode curnode = new DefaultMutableTreeNode("" + refType.uniqueID());
							instancenode.add(curnode);
						}	
					}
				}
				else if(userobject instanceof FieldImpl){
					
				}
				else if(userobject instanceof InterfaceTypeImpl){
					
				}
				else{
					System.out.println(userobject.toString());
				}
			}
		});

		root = new DefaultMutableTreeNode("root");
		
		classTree = new JTree(root);
			
		JScrollPane scroll = new JScrollPane(classTree);
		getContentPane().add(scroll, BorderLayout.CENTER);
		refresh();
		
		classTree.expandRow(0);
		classTree.setRootVisible(false);
		classTree.setShowsRootHandles(true);
		
		setTitle("class info");
		setLocation(200, 200);
		setSize(600, 600);
	}

	public void refresh(){
		HashMap<String, DefaultMutableTreeNode> classNameMap = new HashMap<String, DefaultMutableTreeNode>();
		classNameMap.put("Default", new DefaultMutableTreeNode("Default"));
		root.add(classNameMap.get("Default"));
		
        for (ReferenceType refType : adbg.getAllClasses()) {
        	String name = refType.name();
        	String tag = "Default";
        	int pos = name.indexOf('.');
        	if(-1 != pos)
        		tag = name.substring(0, pos);
        	if(!classNameMap.containsKey(tag)){
        		DefaultMutableTreeNode curcls = new DefaultMutableTreeNode(tag);
        		classNameMap.put(tag, curcls);
        		root.add(curcls);
        	}	
        	DefaultMutableTreeNode curcls = new DefaultMutableTreeNode(name);
        	classNameMap.get(tag).add(curcls);
        	curcls.setUserObject(refType);
        }
	}
}
