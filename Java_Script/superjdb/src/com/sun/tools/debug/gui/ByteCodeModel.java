package com.sun.tools.debug.gui;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.List;

import javax.swing.AbstractListModel;

import com.sun.jdi.Method;
import com.sun.jdi.ReferenceType;


public class ByteCodeModel extends AbstractListModel {

	private List<CONSTANT_BASE> constarr = null;
	private List<String> disbytearr = null;
	private byte[] constpool = null;
	private byte[] bytecodes = null;
	private int bytecodetype = 0;//0:java bytecode  1:dalvik bytecode
	public int selectedline = -1;

	public static int CONSTANT_Class =				7;
	public static int CONSTANT_Fieldref =			9;
	public static int CONSTANT_Methodref = 			10;
	public static int CONSTANT_InterfaceMethodref = 11;
	public static int CONSTANT_String =				8;
	public static int CONSTANT_Integer =			3;
	public static int CONSTANT_Float = 				4;
	public static int CONSTANT_Long =				5;
	public static int CONSTANT_Double =				6;
	public static int CONSTANT_NameAndType =		12;
	public static int CONSTANT_Utf8 =				1;
	public static int CONSTANT_MethodHandle = 		15;
	public static int CONSTANT_MethodType =			16;
	public static int CONSTANT_InvokeDynamic =		18;
	
	public static int opcode_nop	 		= 0x00;
	public static int opcode_aconst_null	= 0x01;
	public static int opcode_iconst_m1		= 0x02;
	public static int opcode_iconst_0	 	= 0x03;
	public static int opcode_iconst_1	 	= 0x04;
	public static int opcode_iconst_2	 	= 0x05;
	public static int opcode_iconst_3	 	= 0x06;
	public static int opcode_iconst_4	 	= 0x07;
	public static int opcode_iconst_5	 	= 0x08;
	public static int opcode_lconst_0	 	= 0x09;
	public static int opcode_lconst_1	 	= 0x0a;
	public static int opcode_fconst_0	 	= 0x0b;
	public static int opcode_fconst_1	 	= 0x0c;
	public static int opcode_fconst_2	 	= 0x0d;
	public static int opcode_dconst_0	 	= 0x0e;
	public static int opcode_dconst_1	 	= 0x0f;
	public static int opcode_bipush	 		= 0x10;
	public static int opcode_sipush	 		= 0x11;
	public static int opcode_ldc	 		= 0x12;
	public static int opcode_ldc_w	 		= 0x13;
	public static int opcode_ldc2_w	 		= 0x14;
	public static int opcode_iload	 		= 0x15;
	public static int opcode_lload	 		= 0x16;
	public static int opcode_fload	 		= 0x17;
	public static int opcode_dload	 		= 0x18;
	public static int opcode_aload	 		= 0x19;
	public static int opcode_iload_0	 	= 0x1a;
	public static int opcode_iload_1	 	= 0x1b;
	public static int opcode_iload_2	 	= 0x1c;
	public static int opcode_iload_3	 	= 0x1d;
	public static int opcode_lload_0	 	= 0x1e;
	public static int opcode_lload_1	 	= 0x1f;
	public static int opcode_lload_2	 	= 0x20;
	public static int opcode_lload_3	 	= 0x21;
	public static int opcode_fload_0	 	= 0x22;
	public static int opcode_fload_1	 	= 0x23;
	public static int opcode_fload_2	 	= 0x24;
	public static int opcode_fload_3	 	= 0x25;
	public static int opcode_dload_0	 	= 0x26;
	public static int opcode_dload_1	 	= 0x27;
	public static int opcode_dload_2	 	= 0x28;
	public static int opcode_dload_3	 	= 0x29;
	public static int opcode_aload_0	 	= 0x2a;
	public static int opcode_aload_1	 	= 0x2b;
	public static int opcode_aload_2	 	= 0x2c;
	public static int opcode_aload_3	 	= 0x2d;
	public static int opcode_iaload	 		= 0x2e;
	public static int opcode_laload	 		= 0x2f;
	public static int opcode_faload	 		= 0x30;
	public static int opcode_daload	 		= 0x31;
	public static int opcode_aaload	 		= 0x32;
	public static int opcode_baload	 		= 0x33;
	public static int opcode_caload	 		= 0x34;
	public static int opcode_saload	 		= 0x35;
	public static int opcode_istore	 		= 0x36;
	public static int opcode_lstore	 		= 0x37;
	public static int opcode_fstore	 		= 0x38;
	public static int opcode_dstore	 		= 0x39;
	public static int opcode_astore	 		= 0x3a;
	public static int opcode_istore_0	 	= 0x3b;
	public static int opcode_istore_1	 	= 0x3c;
	public static int opcode_istore_2	 	= 0x3d;
	public static int opcode_istore_3	 	= 0x3e;
	public static int opcode_lstore_0	 	= 0x3f;
	public static int opcode_lstore_1	 	= 0x40;
	public static int opcode_lstore_2	 	= 0x41;
	public static int opcode_lstore_3	 	= 0x42;
	public static int opcode_fstore_0	 	= 0x43;
	public static int opcode_fstore_1	 	= 0x44;
	public static int opcode_fstore_2	 	= 0x45;
	public static int opcode_fstore_3	 	= 0x46;
	public static int opcode_dstore_0	 	= 0x47;
	public static int opcode_dstore_1	 	= 0x48;
	public static int opcode_dstore_2	 	= 0x49;
	public static int opcode_dstore_3	 	= 0x4a;
	public static int opcode_astore_0	 	= 0x4b;
	public static int opcode_astore_1	 	= 0x4c;
	public static int opcode_astore_2	 	= 0x4d;
	public static int opcode_astore_3	 	= 0x4e;
	public static int opcode_iastore	 	= 0x4f;
	public static int opcode_lastore	 	= 0x50;
	public static int opcode_fastore	 	= 0x51;
	public static int opcode_dastore	 	= 0x52;
	public static int opcode_aastore	 	= 0x53;
	public static int opcode_bastore	 	= 0x54;
	public static int opcode_castore	 	= 0x55;
	public static int opcode_sastore	 	= 0x56;
	public static int opcode_pop	 		= 0x57;
	public static int opcode_pop2	 		= 0x58;
	public static int opcode_dup	 		= 0x59;
	public static int opcode_dup_x1	 		= 0x5a;
	public static int opcode_dup_x2	 		= 0x5b;
	public static int opcode_dup2	 		= 0x5c;
	public static int opcode_dup2_x1	 	= 0x5d;
	public static int opcode_dup2_x2	 	= 0x5e;
	public static int opcode_swap	 		= 0x5f;
	public static int opcode_iadd	 		= 0x60;
	public static int opcode_ladd	 		= 0x61;
	public static int opcode_fadd	 		= 0x62;
	public static int opcode_dadd	 		= 0x63;
	public static int opcode_isub	 		= 0x64;
	public static int opcode_lsub	 		= 0x65;
	public static int opcode_fsub	 		= 0x66;
	public static int opcode_dsub	 		= 0x67;
	public static int opcode_imul	 		= 0x68;
	public static int opcode_lmul	 		= 0x69;
	public static int opcode_fmul	 		= 0x6a;
	public static int opcode_dmul	 		= 0x6b;
	public static int opcode_idiv	 		= 0x6c;
	public static int opcode_ldiv	 		= 0x6d;
	public static int opcode_fdiv	 		= 0x6e;
	public static int opcode_ddiv	 		= 0x6f;
	public static int opcode_irem	 		= 0x70;
	public static int opcode_lrem	 		= 0x71;
	public static int opcode_frem	 		= 0x72;
	public static int opcode_drem	 		= 0x73;
	public static int opcode_ineg	 		= 0x74;
	public static int opcode_lneg	 		= 0x75;
	public static int opcode_fneg	 		= 0x76;
	public static int opcode_dneg	 		= 0x77;
	public static int opcode_ishl	 		= 0x78;
	public static int opcode_lshl	 		= 0x79;
	public static int opcode_ishr	 		= 0x7a;
	public static int opcode_lshr	 		= 0x7b;
	public static int opcode_iushr	 		= 0x7c;
	public static int opcode_lushr	 		= 0x7d;
	public static int opcode_iand	 		= 0x7e;
	public static int opcode_land	 		= 0x7f;
	public static int opcode_ior	 		= 0x80;
	public static int opcode_lor	 		= 0x81;
	public static int opcode_ixor	 		= 0x82;
	public static int opcode_lxor	 		= 0x83;
	public static int opcode_iinc	 		= 0x84;
	public static int opcode_i2l	 		= 0x85;
	public static int opcode_i2f	 		= 0x86;
	public static int opcode_i2d	 		= 0x87;
	public static int opcode_l2i	 		= 0x88;
	public static int opcode_l2f	 		= 0x89;
	public static int opcode_l2d	 		= 0x8a;
	public static int opcode_f2i	 		= 0x8b;
	public static int opcode_f2l	 		= 0x8c;
	public static int opcode_f2d	 		= 0x8d;
	public static int opcode_d2i	 		= 0x8e;
	public static int opcode_d2l	 		= 0x8f;
	public static int opcode_d2f	 		= 0x90;
	public static int opcode_i2b	 		= 0x91;
	public static int opcode_i2c	 		= 0x92;
	public static int opcode_i2s	 		= 0x93;
	public static int opcode_lcmp	 		= 0x94;
	public static int opcode_fcmpl	 		= 0x95;
	public static int opcode_fcmpg	 		= 0x96;
	public static int opcode_dcmpl	 		= 0x97;
	public static int opcode_dcmpg	 		= 0x98;
	public static int opcode_ifeq	 		= 0x99;
	public static int opcode_ifne	 		= 0x9a;
	public static int opcode_iflt	 		= 0x9b;
	public static int opcode_ifge	 		= 0x9c;
	public static int opcode_ifgt	 		= 0x9d;
	public static int opcode_ifle	 		= 0x9e;
	public static int opcode_if_icmpeq		= 0x9f;
	public static int opcode_if_icmpne		= 0xa0;
	public static int opcode_if_icmplt		= 0xa1;
	public static int opcode_if_icmpge		= 0xa2;
	public static int opcode_if_icmpgt		= 0xa3;
	public static int opcode_if_icmple		= 0xa4;
	public static int opcode_if_acmpeq		= 0xa5;
	public static int opcode_if_acmpne		= 0xa6;
	public static int opcode_goto	 		= 0xa7;
	public static int opcode_jsr	 		= 0xa8;
	public static int opcode_ret	 		= 0xa9;
	public static int opcode_tableswitch	= 0xaa;
	public static int opcode_lookupswitch	= 0xab;
	public static int opcode_ireturn	 	= 0xac;
	public static int opcode_lreturn	 	= 0xad;
	public static int opcode_freturn	 	= 0xae;
	public static int opcode_dreturn	 	= 0xaf;
	public static int opcode_areturn	 	= 0xb0;
	public static int opcode_Return	 		= 0xb1;
	public static int opcode_getstatic		= 0xb2;
	public static int opcode_putstatic		= 0xb3;
	public static int opcode_getfield	 	= 0xb4;
	public static int opcode_putfield	 	= 0xb5;
	public static int opcode_invokevirtual	= 0xb6;
	public static int opcode_invokespecial	= 0xb7;
	public static int opcode_invokestatic 	= 0xb8;
	public static int opcode_invokeinterface= 0xb9;
	public static int opcode_invokedynamic	= 0xba;
	public static int opcode_new	 		= 0xbb;
	public static int opcode_newarray	 	= 0xbc;
	public static int opcode_anewarray	 	= 0xbd;
	public static int opcode_arraylength	= 0xbe;
	public static int opcode_athrow	 		= 0xbf;
	public static int opcode_checkcast		= 0xc0;
	public static int opcode_instanceof	 	= 0xc1;
	public static int opcode_monitorenter	= 0xc2;
	public static int opcode_monitorexit	= 0xc3;
	public static int opcode_wide	 		= 0xc4;
	public static int opcode_multianewarray	= 0xc5;
	public static int opcode_ifnull	 		= 0xc6;
	public static int opcode_ifnonnull	 	= 0xc7;
	public static int opcode_goto_w	 		= 0xc8;
	public static int opcode_jsr_w	 		= 0xc9;
	public static int opcode_breakpoint	 	= 0xca;
	public static int opcode_impdep1	 	= 0xfe;
	public static int opcode_impdep2		= 0xff;
	
	public static String[] opnames;
	
	public static byte no_body		 		= 0;
	public static byte index_body			= 1;
	public static byte index_const_body		= 2;
	public static byte sipush_body			= 3;
	public static byte bipush_body			= 4; 
	public static byte newarray_body		= 5;
	public static byte indexbyte_1_2_body	= 6;
	public static byte branchbyte1_2_body	= 7;
	public static byte branchbyte1_4_body	= 8; 
	public static byte invokeinterface_body	= 9;
	public static byte invokedynamic_body	= 10;
	public static byte multianewarray_body	= 11;
	public static byte wide_body		 	= 12;
	public static byte tableswitch_body		= 13;
	public static byte lookupswitch_body	= 14;
	public static byte index_v2_body		= 15;
	
	private class CONSTANT_BASE{
		int tag;
		int size;
		public CONSTANT_BASE(int index){
			this.tag = constpool[index];
		}
	}
	
	private class CONSTANT_CLASS extends CONSTANT_BASE{
		int name_index;
		public CONSTANT_CLASS(int index){
			super(index);
			size = 3;
			name_index = IntUtils.byteToInt(constpool[index + 1], constpool[index + 2]);
		}
	}
	
	private class CONSTANT_FIELDREF extends CONSTANT_BASE{
		int class_index;
		int name_and_type_index;
		public CONSTANT_FIELDREF(int index){
			super(index);
			size = 5;
			class_index = IntUtils.byteToInt(constpool[index + 1], constpool[index + 2]);
			name_and_type_index = IntUtils.byteToInt(constpool[index + 3], constpool[index + 4]);
		}
	}
	
	private class CONSTANT_METHODREF extends CONSTANT_BASE{
		int class_index;
		int name_and_type_index;
		public CONSTANT_METHODREF(int index){
			super(index);
			size = 5;
			class_index = IntUtils.byteToInt(constpool[index + 1], constpool[index + 2]);
			name_and_type_index = IntUtils.byteToInt(constpool[index + 3], constpool[index + 4]);
		}
	}
	
	private class CONSTANT_INTERFACEMETHODREF extends CONSTANT_BASE{
		int class_index;
		int name_and_type_index;
		public CONSTANT_INTERFACEMETHODREF(int index){
			super(index);
			size = 5;
			class_index = IntUtils.byteToInt(constpool[index + 1], constpool[index + 2]);
			name_and_type_index = IntUtils.byteToInt(constpool[index + 3], constpool[index + 4]);
		}
	}
	
	private class CONSTANT_STRING extends CONSTANT_BASE{
		int string_index;
		public CONSTANT_STRING(int index){
			super(index);
			size = 3;
			string_index = IntUtils.byteToInt(constpool[index + 1], constpool[index + 2]);
		}
	}
	
	private class CONSTANT_INTEGER extends CONSTANT_BASE{
		int bytes;
		public CONSTANT_INTEGER(int index){
			super(index);
			size = 5;
			bytes = IntUtils.byteToInt(constpool[index + 1], constpool[index + 2], constpool[index + 3], constpool[index + 4]);
		}
	}
	
	private class CONSTANT_FLOAT extends CONSTANT_BASE{
		float bytes;
		public CONSTANT_FLOAT(int index){
			super(index);
			size = 5;
			bytes = Float.intBitsToFloat(IntUtils.byteToInt(constpool[index + 1], constpool[index + 2], 
					constpool[index + 3], constpool[index + 4]));
		}
	}
	
	private class CONSTANT_LONG extends CONSTANT_BASE{
		long bytes;
		public CONSTANT_LONG(int index){
			super(index);
			size = 9;
			bytes = IntUtils.byteToInt(constpool[index + 1], constpool[index + 2], constpool[index + 3], constpool[index + 4],
					constpool[index + 5], constpool[index + 6], constpool[index + 7], constpool[index + 8]);
		}
	}
	
	private class CONSTANT_DOUBLE extends CONSTANT_BASE{
		double bytes;
		public CONSTANT_DOUBLE(int index){
			super(index);
			size = 9;
			bytes = Double.longBitsToDouble(IntUtils.byteToInt(constpool[index + 1], constpool[index + 2], constpool[index + 3],
					constpool[index + 4], constpool[index + 5], constpool[index + 6], constpool[index + 7], constpool[index + 8]));
		}
	}
	
	private class CONSTANT_NAMEANDTYPE extends CONSTANT_BASE{
		int name_index;
		int descriptor_index;
		public CONSTANT_NAMEANDTYPE(int index){
			super(index);
			size = 5;
			name_index = IntUtils.byteToInt(constpool[index + 1], constpool[index + 2]);
			descriptor_index = IntUtils.byteToInt(constpool[index + 3], constpool[index + 4]);
		}
	}
	
	private class CONSTANT_UTF8 extends CONSTANT_BASE{
		int length;
		String str;
		public CONSTANT_UTF8(int index){
			super(index);
			size = 3;
			length = IntUtils.byteToInt(constpool[index + 1], constpool[index + 2]);
			str = "";
			try {
				if(length > 0){
					size += length;
					byte[] tmp = new byte[length];
					for(int i = 0;i < tmp.length; i++){
						tmp[i] = constpool[index + 3 + i];
					}
					str = new String(tmp, "utf-8");
				}
			} 
			catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
		}
	}
	
	private class CONSTANT_METHODHANDLE extends CONSTANT_BASE{
		int reference_kind;
		int reference_index;
		public CONSTANT_METHODHANDLE(int index){
			super(index);
			size = 4;
			reference_kind = constpool[index + 1];
			reference_index = IntUtils.byteToInt(constpool[index + 2], constpool[index + 3]);
		}
	}
	
	private class CONSTANT_METHODTYPE extends CONSTANT_BASE{
		int descriptor_index;
		public CONSTANT_METHODTYPE(int index){
			super(index);
			size = 3;
			descriptor_index = IntUtils.byteToInt(constpool[index + 1], constpool[index + 2]);
		}
	}
	
	private class CONSTANT_INVOKEDYNAMIC extends CONSTANT_BASE{
		int bootstrap_method_attr_index;
		int name_and_type_index;
		public CONSTANT_INVOKEDYNAMIC(int index){
			super(index);
			size = 5;
			bootstrap_method_attr_index = IntUtils.byteToInt(constpool[index + 1], constpool[index + 2]);
			name_and_type_index = IntUtils.byteToInt(constpool[index + 3], constpool[index + 4]);
		}
	}
	
	private Class[] clsmap;
	private byte[] array_opcodes_body_type;
	
	public String get_constant_pool_Utf8(int index){
		if(constarr == null || index >= constarr.size())
			return "unknown";
		
		CONSTANT_BASE obj = constarr.get(index);
		if(obj.tag == CONSTANT_Class){
			return get_constant_pool_Utf8(((CONSTANT_CLASS)obj).name_index);
		}
		if(obj.tag == CONSTANT_String){
			return get_constant_pool_Utf8(((CONSTANT_STRING)obj).string_index);
		}
		if(obj.tag == CONSTANT_InvokeDynamic){
			CONSTANT_INVOKEDYNAMIC invoke = (CONSTANT_INVOKEDYNAMIC)obj;
			return String.format("%s.%s", get_constant_pool_Utf8(invoke.bootstrap_method_attr_index),
					get_constant_pool_Utf8(invoke.name_and_type_index));
		}
		if(obj.tag == CONSTANT_NameAndType){
			CONSTANT_NAMEANDTYPE nameandtype = (CONSTANT_NAMEANDTYPE)obj;
			return String.format("%s -> %s", get_constant_pool_Utf8(nameandtype.name_index), 
					get_constant_pool_Utf8(nameandtype.descriptor_index));
		}
		if(obj.tag == CONSTANT_Fieldref){
			CONSTANT_FIELDREF ref = (CONSTANT_FIELDREF)obj;
			return String.format("%s.%s", get_constant_pool_Utf8(ref.class_index), 
					get_constant_pool_Utf8(ref.name_and_type_index));
		}
		if(obj.tag == CONSTANT_Methodref){
			CONSTANT_METHODREF ref = (CONSTANT_METHODREF)obj;
			return String.format("%s.%s", get_constant_pool_Utf8(ref.class_index), 
					get_constant_pool_Utf8(ref.name_and_type_index));
		}
		if(obj.tag == CONSTANT_InterfaceMethodref){
			CONSTANT_INTERFACEMETHODREF ref = (CONSTANT_INTERFACEMETHODREF)obj;
			return String.format("%s.%s", get_constant_pool_Utf8(ref.class_index), 
					get_constant_pool_Utf8(ref.name_and_type_index));
		}
		if(obj.tag == CONSTANT_Integer){
			return String.format("%d", ((CONSTANT_INTEGER)obj).bytes);
		}
		if(obj.tag == CONSTANT_Long){
			return String.format("%Ld", ((CONSTANT_LONG)obj).bytes);
		}
		if(obj.tag == CONSTANT_Float){
			return String.format("%f", ((CONSTANT_FLOAT)obj).bytes);
		}
		if(obj.tag == CONSTANT_Double){
			return String.format("%Lf", ((CONSTANT_DOUBLE)obj).bytes);
		}
		if(obj.tag == CONSTANT_Utf8){
			return ((CONSTANT_UTF8)obj).str;
		}
		return "unknown";
	}
	
	public ByteCodeModel(ReferenceType referenceType, Method method, long codeindex){
		if(referenceType == null || method == null)
			return;
		
		clsmap = new Class[256];
		for(int i = 0;i < 256; i++){
			clsmap[i] = CONSTANT_BASE.class;
		}
		clsmap[CONSTANT_Class] = CONSTANT_CLASS.class;
		clsmap[CONSTANT_Fieldref] = CONSTANT_FIELDREF.class;
		clsmap[CONSTANT_Methodref] = CONSTANT_METHODREF.class;
		clsmap[CONSTANT_InterfaceMethodref] = CONSTANT_INTERFACEMETHODREF.class;
		clsmap[CONSTANT_String] = CONSTANT_STRING.class;
		clsmap[CONSTANT_Integer] = CONSTANT_INTEGER.class;
		clsmap[CONSTANT_Float] = CONSTANT_FLOAT.class;
		clsmap[CONSTANT_Long] = CONSTANT_LONG.class;
		clsmap[CONSTANT_Double] = CONSTANT_DOUBLE.class;
		clsmap[CONSTANT_NameAndType] = CONSTANT_NAMEANDTYPE.class;
		clsmap[CONSTANT_Utf8] = CONSTANT_UTF8.class;
		clsmap[CONSTANT_MethodHandle] = CONSTANT_METHODHANDLE.class;
		clsmap[CONSTANT_MethodType] = CONSTANT_METHODTYPE.class;
		clsmap[CONSTANT_InvokeDynamic] = CONSTANT_INVOKEDYNAMIC.class;
		
		array_opcodes_body_type = new byte[256];
		for(int i = 0;i < 256;i++){
			array_opcodes_body_type[i] = 0;
		}
		array_opcodes_body_type[opcode_tableswitch]=tableswitch_body;
		array_opcodes_body_type[opcode_lookupswitch]=lookupswitch_body;
		array_opcodes_body_type[opcode_bipush]=bipush_body; 
		array_opcodes_body_type[opcode_iload]=index_body; 
		array_opcodes_body_type[opcode_lload]=index_body; 
		array_opcodes_body_type[opcode_fload]=index_body; 
		array_opcodes_body_type[opcode_dload]=index_body; 
		array_opcodes_body_type[opcode_aload]=index_body; 
		array_opcodes_body_type[opcode_istore]=index_body;  
		array_opcodes_body_type[opcode_lstore]=index_body;  
		array_opcodes_body_type[opcode_fstore]=index_body; 
		array_opcodes_body_type[opcode_dstore]=index_body; 
		array_opcodes_body_type[opcode_astore]=index_body;  
		array_opcodes_body_type[opcode_sipush]=sipush_body; 
		array_opcodes_body_type[opcode_ldc]=index_v2_body; 
		array_opcodes_body_type[opcode_ldc_w]=indexbyte_1_2_body; 
		array_opcodes_body_type[opcode_ldc2_w]=indexbyte_1_2_body;
		array_opcodes_body_type[opcode_iinc]=index_const_body; 
		array_opcodes_body_type[opcode_ifeq]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_ifne]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_iflt]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_ifge]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_ifgt]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_ifle]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_if_icmpeq]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_if_icmpne]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_if_icmplt]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_if_icmpge]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_if_icmpgt]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_if_icmple]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_if_acmpeq]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_if_acmpne]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_goto]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_jsr]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_ret]=index_body;
		array_opcodes_body_type[opcode_getstatic]=indexbyte_1_2_body; 
		array_opcodes_body_type[opcode_putstatic]=indexbyte_1_2_body; 
		array_opcodes_body_type[opcode_getfield]=indexbyte_1_2_body; 
		array_opcodes_body_type[opcode_putfield]=indexbyte_1_2_body; 
		array_opcodes_body_type[opcode_new]=indexbyte_1_2_body; 
		array_opcodes_body_type[opcode_newarray]=newarray_body; 
		array_opcodes_body_type[opcode_invokevirtual]=indexbyte_1_2_body; 
		array_opcodes_body_type[opcode_invokespecial]=indexbyte_1_2_body; 
		array_opcodes_body_type[opcode_invokestatic]=indexbyte_1_2_body; 
		array_opcodes_body_type[opcode_anewarray]=indexbyte_1_2_body; 
		array_opcodes_body_type[opcode_checkcast]=indexbyte_1_2_body; 
		array_opcodes_body_type[opcode_instanceof]=indexbyte_1_2_body; 
		array_opcodes_body_type[opcode_wide]=wide_body; 
		array_opcodes_body_type[opcode_multianewarray]=multianewarray_body; 
		array_opcodes_body_type[opcode_ifnull]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_ifnonnull]=branchbyte1_2_body; 
		array_opcodes_body_type[opcode_invokeinterface]=invokeinterface_body; 
		array_opcodes_body_type[opcode_invokedynamic]=invokedynamic_body; 
		array_opcodes_body_type[opcode_goto_w]=branchbyte1_4_body;
		array_opcodes_body_type[opcode_jsr_w]=branchbyte1_4_body; 

		opnames = new String[]{
			"nop","aconst_null","iconst_m1","iconst_0","iconst_1","iconst_2","iconst_3",
			"iconst_4","iconst_5","lconst_0","lconst_1","fconst_0","fconst_1","fconst_2",
			"dconst_0","dconst_1","bipush","sipush","ldc","ldc_w","ldc2_w","iload","lload",
			"fload","dload","aload","iload_0","iload_1","iload_2","iload_3","lload_0",
			"lload_1","lload_2","lload_3","fload_0","fload_1","fload_2","fload_3","dload_0",
			"dload_1","dload_2","dload_3","aload_0","aload_1","aload_2","aload_3","iaload",
			"laload","faload","daload","aaload","baload","caload","saload","istore","lstore",
			"fstore","dstore","astore","istore_0","istore_1","istore_2","istore_3","lstore_0",
			"lstore_1","lstore_2","lstore_3","fstore_0","fstore_1","fstore_2","fstore_3",
			"dstore_0","dstore_1","dstore_2","dstore_3","astore_0","astore_1","astore_2",
			"astore_3","iastore","lastore","fastore","dastore","aastore","bastore","castore",
			"sastore","pop","pop2","dup","dup_x1","dup_x2","dup2","dup2_x1","dup2_x2","swap",
			"iadd","ladd","fadd","dadd","isub","lsub","fsub","dsub","imul","lmul","fmul",
			"dmul","idiv","ldiv","fdiv","ddiv","irem","lrem","frem","drem","ineg","lneg",
			"fneg","dneg","ishl","lshl","ishr","lshr","iushr","lushr","iand","land","ior",
			"lor","ixor","lxor","iinc","i2l","i2f","i2d","l2i","l2f","l2d","f2i","f2l","f2d",
			"d2i","d2l","d2f","i2b","i2c","i2s","lcmp","fcmpl","fcmpg","dcmpl","dcmpg","ifeq",
			"ifne","iflt","ifge","ifgt","ifle","if_icmpeq","if_icmpne","if_icmplt","if_icmpge",
			"if_icmpgt","if_icmple","if_acmpeq","if_acmpne","goto","jsr","ret","tableswitch",
			"lookupswitch","ireturn","lreturn","freturn","dreturn","areturn","Return",
			"getstatic","putstatic","getfield","putfield","invokevirtual","invokespecial",
			"invokestatic","invokeinterface","invokedynamic","new","newarray","anewarray",
			"arraylength","athrow","checkcast","instanceof","monitorenter","monitorexit",
			"wide","multianewarray","ifnull","ifnonnull","goto_w","jsr_w","breakpoint",
			"unused1","unused2","unused3","unused4","unused5","unused6","unused7","unused8",
			"unused9","unused10","unused11","unused12","unused13","unused14","unused15",
			"unused16","unused17","unused18","unused19","unused20","unused21","unused22",
			"unused23","unused24","unused25","unused26","unused27","unused28","unused29",
			"unused30","unused31","unused32","unused33","unused34","unused35","unused36",
			"unused37","unused38","unused39","unused40","unused41","unused42","unused43",
			"unused44","unused45","unused46","unused47","unused48","unused49","unused50",
			"unused51","impdep1","impdep2",
		};
		
		try{
			bytecodes = method.bytecodes();
			constpool = referenceType.constantPool();
			
			buildConstantPool();
			buildDisByte(codeindex);
		}
		catch(Exception e){
			
		}
		//��ʼ��ѡ����
	}
	
	private void buildConstantPool(){
		int index = 0;
		try{
			constarr = new ArrayList<CONSTANT_BASE>();
			for(index = 0;index < constpool.length;){
				Class cls = clsmap[constpool[index]];
				Constructor con = cls.getConstructors()[0];
				CONSTANT_BASE obj = (CONSTANT_BASE) con.newInstance(this, index);
				index += obj.size;
				constarr.add(obj);
			}
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}
	
	private void buildDisByte(long codeindex){
		disbytearr = new ArrayList<String>();
		for(int i = 0;i < bytecodes.length;){
			if(selectedline == -1 && i >= codeindex)
				selectedline = disbytearr.size();
			String instructstr = opnames[bytecodes[i]&0xff];
			byte operation = array_opcodes_body_type[bytecodes[i]&0xff];
			if(operation == index_body){
				instructstr += String.format(" %d", bytecodes[i + 1]&0xff);
				i += 2;
			}
			else if(operation == index_v2_body){
				instructstr += " " + get_constant_pool_Utf8(bytecodes[i + 1]&0xff);
				i += 2;
			}
			else if(operation == index_const_body){
				instructstr += String.format(" %d by %d", bytecodes[i + 1]&0xff, bytecodes[i + 2]);
				i += 3;
			}
			else if(operation == sipush_body){
				instructstr += String.format(" %d", IntUtils.byteToInt(bytecodes[i + 1], bytecodes[i + 2]));
				i += 3;
			}
			else if(operation == bipush_body){
				instructstr += String.format(" %d", bytecodes[i + 1]&0xff);
				i += 2;
			}
			else if(operation == newarray_body){
				int atype = bytecodes[i + 1]&0xff;
				String[] typestr = new String[256];
				for(int j = 0;j < 256;j++){
					typestr[i] = "unknown";
				}
				typestr[4] = " boolean";
				typestr[5] = " char";
				typestr[6] = " float";
				typestr[7] = " double";
				typestr[8] = " byte";
				typestr[9] = " short";
				typestr[10] = " int";
				typestr[11] = " long";
				instructstr += typestr[atype];
				i += 2;
			}
			else if(operation == multianewarray_body){
				
				instructstr += String.format(" %s dimensions %d", get_constant_pool_Utf8(IntUtils.byteToInt(bytecodes[i + 1], 
						bytecodes[i + 2])),bytecodes[i + 3]&0xff);
				i += 4;
			}
			else if(operation == wide_body){
				String operation2 = opnames[bytecodes[i + 1]&0xff];
				String str2 = get_constant_pool_Utf8(IntUtils.byteToInt(bytecodes[i + 2], bytecodes[i + 3]));
				instructstr += String.format(" %s %s", operation2, str2);
				if(bytecodes[i + 1] == opcode_iinc){
					instructstr += String.format(" by %d", IntUtils.byteToInt(bytecodes[i + 4], bytecodes[i + 5]));
					i += 2;
				}
				i += 4;
			}
			else if(operation == tableswitch_body){
				int padding = 4 - (i + 1)%4;
				if(padding == 4)
					padding = 0;
				int defaulttype = IntUtils.byteToInt(bytecodes[i + padding], bytecodes[i + padding + 1], 
						bytecodes[i + padding + 2], bytecodes[i + padding + 3]);
				int lowbyte = IntUtils.byteToInt(bytecodes[i + padding + 4], bytecodes[i + padding + 5], 
						bytecodes[i + padding + 6], bytecodes[i + padding + 7]);
				int highbyte = IntUtils.byteToInt(bytecodes[i + padding + 8], bytecodes[i + padding + 9], 
						bytecodes[i + padding + 10], bytecodes[i + padding + 11]);
			    //int[] jump = new int[highbyte-lowbyte+1];
				instructstr += String.format(" %d to %d", lowbyte, highbyte);
			    i += padding + 12 + 4*(highbyte-lowbyte+1);
			}
			else if(operation == lookupswitch_body){
				int padding = 4 - (i + 1)%4;
				if(padding == 4)
					padding = 0;				
				int defaultbyte = IntUtils.byteToInt(bytecodes[i + padding], bytecodes[i + padding + 1], 
						bytecodes[i + padding + 2], bytecodes[i + padding + 3]);
				int npairs = IntUtils.byteToInt(bytecodes[i + padding + 4], bytecodes[i + padding + 5], 
						bytecodes[i + padding + 6], bytecodes[i + padding + 7]);
			    //struct
			    //{
			    //	i4 match;
			    //	i4 offset;
			    //}match_offset[npairs];
			    i += padding + 8 + 8*npairs;
			}
			else if(operation == invokedynamic_body){
				instructstr += String.format(" %s", get_constant_pool_Utf8(IntUtils.byteToInt(bytecodes[i + 1], bytecodes[i + 2])));
				i += 5;
			}
			else if(operation == indexbyte_1_2_body){
				instructstr += String.format(" %s", get_constant_pool_Utf8(IntUtils.byteToInt(bytecodes[i + 1], bytecodes[i + 2])));
				i += 3;
			}
			else if(operation == branchbyte1_2_body){
				instructstr += String.format(" %d", IntUtils.byteToInt(bytecodes[i + 1], bytecodes[i + 2]));
				i += 3;
			}
			else if(operation == branchbyte1_4_body){
				instructstr += String.format(" %d", IntUtils.byteToInt(bytecodes[i + 1], bytecodes[i + 2], bytecodes[i + 3], bytecodes[i + 4]));
				i += 5;
			}
			else if(operation == invokeinterface_body){
				instructstr += String.format(" %s count %d", get_constant_pool_Utf8(IntUtils.byteToInt(bytecodes[i + 1], bytecodes[i + 2])), bytecodes[i + 3]&0xff);
				i += 5;
			}
			else{
				i += 1;
			}
			disbytearr.add(String.format("%04x:%s", i, instructstr));
		}
	}
	
	@Override
	public int getSize() {
		if(disbytearr != null){
			return disbytearr.size();
		}
		return 0;
	}

	@Override
	public Object getElementAt(int index) {
		if(disbytearr != null){
			return new SourceModel.Line(disbytearr.get(index));
		}
		return null;
	}

}
