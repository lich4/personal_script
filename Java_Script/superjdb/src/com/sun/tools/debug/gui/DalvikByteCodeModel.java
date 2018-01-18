package com.sun.tools.debug.gui;

import java.io.File;
import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.AbstractListModel;

import com.sun.jdi.Method;
import com.sun.jdi.ReferenceType;

public class DalvikByteCodeModel extends AbstractListModel {
	public static int opcode_nopcode                      = 0x00;
	public static int opcode_move                         = 0x01;
	public static int opcode_move_from16                  = 0x02;
	public static int opcode_move_16                      = 0x03;
	public static int opcode_move_wide                    = 0x04;
	public static int opcode_move_wide_from16             = 0x05;
	public static int opcode_move_wide_16                 = 0x06;
	public static int opcode_move_object                  = 0x07;
	public static int opcode_move_object_from16           = 0x08;
	public static int opcode_move_object_16               = 0x09;
	public static int opcode_move_result                  = 0x0a;
	public static int opcode_move_result_wide             = 0x0b;
	public static int opcode_move_result_object           = 0x0c;
	public static int opcode_move_exception               = 0x0d;
	public static int opcode_return_void                  = 0x0e;
	public static int opcode_return                       = 0x0f;
	public static int opcode_return_wide                  = 0x10;
	public static int opcode_return_object                = 0x11;
	public static int opcode_const_4                      = 0x12;
	public static int opcode_const_16                     = 0x13;
	public static int opcode_const                        = 0x14;
	public static int opcode_const_high16                 = 0x15;
	public static int opcode_const_wide_16                = 0x16;
	public static int opcode_const_wide_32                = 0x17;
	public static int opcode_const_wide                   = 0x18;
	public static int opcode_const_wide_high16            = 0x19;
	public static int opcode_const_string                 = 0x1a;
	public static int opcode_const_string_jumbo           = 0x1b;
	public static int opcode_const_class                  = 0x1c;
	public static int opcode_monitor_enter                = 0x1d;
	public static int opcode_monitor_exit                 = 0x1e;
	public static int opcode_check_cast                   = 0x1f;
	public static int opcode_instance_of                  = 0x20;
	public static int opcode_array_length                 = 0x21;
	public static int opcode_new_instance                 = 0x22;
	public static int opcode_new_array                    = 0x23;
	public static int opcode_filled_new_array             = 0x24;
	public static int opcode_filled_new_array_range       = 0x25;
	public static int opcode_fill_array_data              = 0x26;
	public static int opcode_throw                        = 0x27;
	public static int opcode_goto                         = 0x28;
	public static int opcode_goto_16                      = 0x29;
	public static int opcode_goto_32                      = 0x2a;
	public static int opcode_packed_switch                = 0x2b;
	public static int opcode_sparse_switch                = 0x2c;
	public static int opcode_cmpl_float                   = 0x2d;
	public static int opcode_cmpg_float                   = 0x2e;
	public static int opcode_cmpl_double                  = 0x2f;
	public static int opcode_cmpg_double                  = 0x30;
	public static int opcode_cmp_long                     = 0x31;
	public static int opcode_if_eq                        = 0x32;
	public static int opcode_if_ne                        = 0x33;
	public static int opcode_if_lt                        = 0x34;
	public static int opcode_if_ge                        = 0x35;
	public static int opcode_if_gt                        = 0x36;
	public static int opcode_if_le                        = 0x37;
	public static int opcode_if_eqz                       = 0x38;
	public static int opcode_if_nez                       = 0x39;
	public static int opcode_if_ltz                       = 0x3a;
	public static int opcode_if_gez                       = 0x3b;
	public static int opcode_if_gtz                       = 0x3c;
	public static int opcode_if_lez                       = 0x3d;
	public static int opcode_unused_3e                    = 0x3e;
	public static int opcode_unused_3f                    = 0x3f;
	public static int opcode_unused_40                    = 0x40;
	public static int opcode_unused_41                    = 0x41;
	public static int opcode_unused_42                    = 0x42;
	public static int opcode_unused_43                    = 0x43;
	public static int opcode_aget                         = 0x44;
	public static int opcode_aget_wide                    = 0x45;
	public static int opcode_aget_object                  = 0x46;
	public static int opcode_aget_boolean                 = 0x47;
	public static int opcode_aget_byte                    = 0x48;
	public static int opcode_aget_char                    = 0x49;
	public static int opcode_aget_short                   = 0x4a;
	public static int opcode_aput                         = 0x4b;
	public static int opcode_aput_wide                    = 0x4c;
	public static int opcode_aput_object                  = 0x4d;
	public static int opcode_aput_boolean                 = 0x4e;
	public static int opcode_aput_byte                    = 0x4f;
	public static int opcode_aput_char                    = 0x50;
	public static int opcode_aput_short                   = 0x51;
	public static int opcode_iget                         = 0x52;
	public static int opcode_iget_wide                    = 0x53;
	public static int opcode_iget_object                  = 0x54;
	public static int opcode_iget_boolean                 = 0x55;
	public static int opcode_iget_byte                    = 0x56;
	public static int opcode_iget_char                    = 0x57;
	public static int opcode_iget_short                   = 0x58;
	public static int opcode_iput                         = 0x59;
	public static int opcode_iput_wide                    = 0x5a;
	public static int opcode_iput_object                  = 0x5b;
	public static int opcode_iput_boolean                 = 0x5c;
	public static int opcode_iput_byte                    = 0x5d;
	public static int opcode_iput_char                    = 0x5e;
	public static int opcode_iput_short                   = 0x5f;
	public static int opcode_sget                         = 0x60;
	public static int opcode_sget_wide                    = 0x61;
	public static int opcode_sget_object                  = 0x62;
	public static int opcode_sget_boolean                 = 0x63;
	public static int opcode_sget_byte                    = 0x64;
	public static int opcode_sget_char                    = 0x65;
	public static int opcode_sget_short                   = 0x66;
	public static int opcode_sput                         = 0x67;
	public static int opcode_sput_wide                    = 0x68;
	public static int opcode_sput_object                  = 0x69;
	public static int opcode_sput_boolean                 = 0x6a;
	public static int opcode_sput_byte                    = 0x6b;
	public static int opcode_sput_char                    = 0x6c;
	public static int opcode_sput_short                   = 0x6d;
	public static int opcode_invoke_virtual               = 0x6e;
	public static int opcode_invoke_super                 = 0x6f;
	public static int opcode_invoke_direct                = 0x70;
	public static int opcode_invoke_static                = 0x71;
	public static int opcode_invoke_interface             = 0x72;
	public static int opcode_unused_73                    = 0x73;
	public static int opcode_invoke_virtual_range         = 0x74;
	public static int opcode_invoke_super_range           = 0x75;
	public static int opcode_invoke_direct_range          = 0x76;
	public static int opcode_invoke_static_range          = 0x77;
	public static int opcode_invoke_interface_range       = 0x78;
	public static int opcode_unused_79                    = 0x79;
	public static int opcode_unused_7a                    = 0x7a;
	public static int opcode_neg_int                      = 0x7b;
	public static int opcode_not_int                      = 0x7c;
	public static int opcode_neg_long                     = 0x7d;
	public static int opcode_not_long                     = 0x7e;
	public static int opcode_neg_float                    = 0x7f;
	public static int opcode_neg_double                   = 0x80;
	public static int opcode_int_to_long                  = 0x81;
	public static int opcode_int_to_float                 = 0x82;
	public static int opcode_int_to_double                = 0x83;
	public static int opcode_long_to_int                  = 0x84;
	public static int opcode_long_to_float                = 0x85;
	public static int opcode_long_to_double               = 0x86;
	public static int opcode_float_to_int                 = 0x87;
	public static int opcode_float_to_long                = 0x88;
	public static int opcode_float_to_double              = 0x89;
	public static int opcode_double_to_int                = 0x8a;
	public static int opcode_double_to_long               = 0x8b;
	public static int opcode_double_to_float              = 0x8c;
	public static int opcode_int_to_byte                  = 0x8d;
	public static int opcode_int_to_char                  = 0x8e;
	public static int opcode_int_to_short                 = 0x8f;
	public static int opcode_add_int                      = 0x90;
	public static int opcode_sub_int                      = 0x91;
	public static int opcode_mul_int                      = 0x92;
	public static int opcode_div_int                      = 0x93;
	public static int opcode_rem_int                      = 0x94;
	public static int opcode_and_int                      = 0x95;
	public static int opcode_or_int                       = 0x96;
	public static int opcode_xor_int                      = 0x97;
	public static int opcode_shl_int                      = 0x98;
	public static int opcode_shr_int                      = 0x99;
	public static int opcode_ushr_int                     = 0x9a;
	public static int opcode_add_long                     = 0x9b;
	public static int opcode_sub_long                     = 0x9c;
	public static int opcode_mul_long                     = 0x9d;
	public static int opcode_div_long                     = 0x9e;
	public static int opcode_rem_long                     = 0x9f;
	public static int opcode_and_long                     = 0xa0;
	public static int opcode_or_long                      = 0xa1;
	public static int opcode_xor_long                     = 0xa2;
	public static int opcode_shl_long                     = 0xa3;
	public static int opcode_shr_long                     = 0xa4;
	public static int opcode_ushr_long                    = 0xa5;
	public static int opcode_add_float                    = 0xa6;
	public static int opcode_sub_float                    = 0xa7;
	public static int opcode_mul_float                    = 0xa8;
	public static int opcode_div_float                    = 0xa9;
	public static int opcode_rem_float                    = 0xaa;
	public static int opcode_add_double                   = 0xab;
	public static int opcode_sub_double                   = 0xac;
	public static int opcode_mul_double                   = 0xad;
	public static int opcode_div_double                   = 0xae;
	public static int opcode_rem_double                   = 0xaf;
	public static int opcode_add_int_2addr                = 0xb0;
	public static int opcode_sub_int_2addr                = 0xb1;
	public static int opcode_mul_int_2addr                = 0xb2;
	public static int opcode_div_int_2addr                = 0xb3;
	public static int opcode_rem_int_2addr                = 0xb4;
	public static int opcode_and_int_2addr                = 0xb5;
	public static int opcode_or_int_2addr                 = 0xb6;
	public static int opcode_xor_int_2addr                = 0xb7;
	public static int opcode_shl_int_2addr                = 0xb8;
	public static int opcode_shr_int_2addr                = 0xb9;
	public static int opcode_ushr_int_2addr               = 0xba;
	public static int opcode_add_long_2addr               = 0xbb;
	public static int opcode_sub_long_2addr               = 0xbc;
	public static int opcode_mul_long_2addr               = 0xbd;
	public static int opcode_div_long_2addr               = 0xbe;
	public static int opcode_rem_long_2addr               = 0xbf;
	public static int opcode_and_long_2addr               = 0xc0;
	public static int opcode_or_long_2addr                = 0xc1;
	public static int opcode_xor_long_2addr               = 0xc2;
	public static int opcode_shl_long_2addr               = 0xc3;
	public static int opcode_shr_long_2addr               = 0xc4;
	public static int opcode_ushr_long_2addr              = 0xc5;
	public static int opcode_add_float_2addr              = 0xc6;
	public static int opcode_sub_float_2addr              = 0xc7;
	public static int opcode_mul_float_2addr              = 0xc8;
	public static int opcode_div_float_2addr              = 0xc9;
	public static int opcode_rem_float_2addr              = 0xca;
	public static int opcode_add_double_2addr             = 0xcb;
	public static int opcode_sub_double_2addr             = 0xcc;
	public static int opcode_mul_double_2addr             = 0xcd;
	public static int opcode_div_double_2addr             = 0xce;
	public static int opcode_rem_double_2addr             = 0xcf;
	public static int opcode_add_int_lit16                = 0xd0;
	public static int opcode_rsub_int                     = 0xd1;
	public static int opcode_mul_int_lit16                = 0xd2;
	public static int opcode_div_int_lit16                = 0xd3;
	public static int opcode_rem_int_lit16                = 0xd4;
	public static int opcode_and_int_lit16                = 0xd5;
	public static int opcode_or_int_lit16                 = 0xd6;
	public static int opcode_xor_int_lit16                = 0xd7;
	public static int opcode_add_int_lit8                 = 0xd8;
	public static int opcode_rsub_int_lit8                = 0xd9;
	public static int opcode_mul_int_lit8                 = 0xda;
	public static int opcode_div_int_lit8                 = 0xdb;
	public static int opcode_rem_int_lit8                 = 0xdc;
	public static int opcode_and_int_lit8                 = 0xdd;
	public static int opcode_or_int_lit8                  = 0xde;
	public static int opcode_xor_int_lit8                 = 0xdf;
	public static int opcode_shl_int_lit8                 = 0xe0;
	public static int opcode_shr_int_lit8                 = 0xe1;
	public static int opcode_ushr_int_lit8                = 0xe2;
	public static int opcode_iget_volatile                = 0xe3;
	public static int opcode_iput_volatile                = 0xe4;
	public static int opcode_sget_volatile                = 0xe5;
	public static int opcode_sput_volatile                = 0xe6;
	public static int opcode_iget_object_volatile         = 0xe7;
	public static int opcode_iget_wide_volatile           = 0xe8;
	public static int opcode_iput_wide_volatile           = 0xe9;
	public static int opcode_sget_wide_volatile           = 0xea;
	public static int opcode_sput_wide_volatile           = 0xeb;
	public static int opcode_breakpoint                   = 0xec;
	public static int opcode_throw_verification_error     = 0xed;
	public static int opcode_execute_inline               = 0xee;
	public static int opcode_execute_inline_range         = 0xef;
	public static int opcode_invoke_object_init_range     = 0xf0;
	public static int opcode_return_void_barrier          = 0xf1;
	public static int opcode_iget_quick                   = 0xf2;
	public static int opcode_iget_wide_quick              = 0xf3;
	public static int opcode_iget_object_quick            = 0xf4;
	public static int opcode_iput_quick                   = 0xf5;
	public static int opcode_iput_wide_quick              = 0xf6;
	public static int opcode_iput_object_quick            = 0xf7;
	public static int opcode_invoke_virtual_quick         = 0xf8;
	public static int opcode_invoke_virtual_quick_range   = 0xf9;
	public static int opcode_invoke_super_quick           = 0xfa;
	public static int opcode_invoke_super_quick_range     = 0xfb;
	public static int opcode_iput_object_volatile         = 0xfc;
	public static int opcode_sget_object_volatile         = 0xfd;
	public static int opcode_sput_object_volatile         = 0xfe;
	public static int opcode_unused_ff                    = 0xff;
	
	public static int[] gInstructionWidthTable = new int[]{
		1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 2, 3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2,
		2, 1, 2, 2, 3, 3, 3, 1, 1, 2, 3, 3, 3, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0,
		0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,
		3, 3, 3, 0, 3, 3, 3, 3, 3, 0, 0, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 2, 3, 3,
		3, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 2, 2, 2, 0,
	};
	
	public static final int kIndexUnknown 	= 0;
	public static final int kIndexNone		= 1;// has no index
	public static final int kIndexVaries		= 2;// "It depends." Used for throw-verification-error
	public static final int kIndexTypeRef		= 3;// type reference index
	public static final int kIndexStringRef	= 4;// string reference index
	public static final int kIndexMethodRef	= 5;// method reference index
	public static final int kIndexFieldRef	= 6;// field reference index
	public static final int kIndexInlineMethod= 7;// inline method index (for inline linked methods)
	public static final int kIndexVtableOffset= 8;// vtable offset (for static linked methods)
	public static final int kIndexFieldOffset	= 9;// field offset (for static linked fields)
	
	public static final int kFmt00x = 0;// unknown format (also used for "breakpoint" opcode)
	public static final int kFmt10x = 1;// op
	public static final int kFmt12x = 2;// op vA, vB
	public static final int kFmt11n = 3;// op vA, #+B
	public static final int kFmt11x = 4;// op vAA
	public static final int kFmt10t = 5;// op +AA
	public static final int kFmt20bc= 6;// [opt] op AA, thing@BBBB
	public static final int kFmt20t = 7;// op +AAAA
	public static final int kFmt22x = 8;// op vAA, vBBBB
	public static final int kFmt21t = 9;// op vAA, +BBBB
	public static final int kFmt21s =10;// op vAA, #+BBBB
	public static final int kFmt21h =11;// op vAA, #+BBBB00000[00000000]
	public static final int kFmt21c =12;// op vAA, thing@BBBB
	public static final int kFmt23x =13;// op vAA, vBB, vCC
	public static final int kFmt22b =14;// op vAA, vBB, #+CC
	public static final int kFmt22t =15;// op vA, vB, +CCCC
	public static final int kFmt22s =16;// op vA, vB, #+CCCC
	public static final int kFmt22c =17;// op vA, vB, thing@CCCC
	public static final int kFmt22cs=18;// [opt] op vA, vB, field offset CCCC
	public static final int kFmt30t =19;// op +AAAAAAAA
	public static final int kFmt32x =20;// op vAAAA, vBBBB
	public static final int kFmt31i =21;// op vAA, #+BBBBBBBB
	public static final int kFmt31t =22;// op vAA, +BBBBBBBB
	public static final int kFmt31c =23;// op vAA, string@BBBBBBBB
	public static final int kFmt35c =24;// op {vC,vD,vE,vF,vG}, thing@BBBB
	public static final int kFmt35ms=25;// [opt] invoke-virtual+super
	public static final int kFmt3rc =26;// op {vCCCC .. v(CCCC+AA-1)}, thing@BBBB
	public static final int kFmt3rms=27;// [opt] invoke-virtual+super/range
	public static final int kFmt51l =28;// op vAA, #+BBBBBBBBBBBBBBBB
	public static final int kFmt35mi=29;// [opt] inline invoke
	public static final int kFmt3rmi=30;// [opt] inline invoke/range
	
	public static int[] gInstructionFormatTable = new int[]{
	    kFmt10x,  kFmt12x,  kFmt22x,  kFmt32x,  kFmt12x,  kFmt22x,  kFmt32x,
	    kFmt12x,  kFmt22x,  kFmt32x,  kFmt11x,  kFmt11x,  kFmt11x,  kFmt11x,
	    kFmt10x,  kFmt11x,  kFmt11x,  kFmt11x,  kFmt11n,  kFmt21s,  kFmt31i,
	    kFmt21h,  kFmt21s,  kFmt31i,  kFmt51l,  kFmt21h,  kFmt21c,  kFmt31c,
	    kFmt21c,  kFmt11x,  kFmt11x,  kFmt21c,  kFmt22c,  kFmt12x,  kFmt21c,
	    kFmt22c,  kFmt35c,  kFmt3rc,  kFmt31t,  kFmt11x,  kFmt10t,  kFmt20t,
	    kFmt30t,  kFmt31t,  kFmt31t,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,
	    kFmt23x,  kFmt22t,  kFmt22t,  kFmt22t,  kFmt22t,  kFmt22t,  kFmt22t,
	    kFmt21t,  kFmt21t,  kFmt21t,  kFmt21t,  kFmt21t,  kFmt21t,  kFmt00x,
	    kFmt00x,  kFmt00x,  kFmt00x,  kFmt00x,  kFmt00x,  kFmt23x,  kFmt23x,
	    kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,
	    kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt22c,  kFmt22c,
	    kFmt22c,  kFmt22c,  kFmt22c,  kFmt22c,  kFmt22c,  kFmt22c,  kFmt22c,
	    kFmt22c,  kFmt22c,  kFmt22c,  kFmt22c,  kFmt22c,  kFmt21c,  kFmt21c,
	    kFmt21c,  kFmt21c,  kFmt21c,  kFmt21c,  kFmt21c,  kFmt21c,  kFmt21c,
	    kFmt21c,  kFmt21c,  kFmt21c,  kFmt21c,  kFmt21c,  kFmt35c,  kFmt35c,
	    kFmt35c,  kFmt35c,  kFmt35c,  kFmt00x,  kFmt3rc,  kFmt3rc,  kFmt3rc,
	    kFmt3rc,  kFmt3rc,  kFmt00x,  kFmt00x,  kFmt12x,  kFmt12x,  kFmt12x,
	    kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,
	    kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,
	    kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt23x,  kFmt23x,  kFmt23x,
	    kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,
	    kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,
	    kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,
	    kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,  kFmt23x,
	    kFmt23x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,
	    kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,
	    kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,
	    kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,
	    kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt12x,  kFmt22s,  kFmt22s,
	    kFmt22s,  kFmt22s,  kFmt22s,  kFmt22s,  kFmt22s,  kFmt22s,  kFmt22b,
	    kFmt22b,  kFmt22b,  kFmt22b,  kFmt22b,  kFmt22b,  kFmt22b,  kFmt22b,
	    kFmt22b,  kFmt22b,  kFmt22b,  kFmt22c,  kFmt22c,  kFmt21c,  kFmt21c,
	    kFmt22c,  kFmt22c,  kFmt22c,  kFmt21c,  kFmt21c,  kFmt00x,  kFmt20bc,
	    kFmt35mi, kFmt3rmi, kFmt35c,  kFmt10x,  kFmt22cs, kFmt22cs, kFmt22cs,
	    kFmt22cs, kFmt22cs, kFmt22cs, kFmt35ms, kFmt3rms, kFmt35ms, kFmt3rms,
	    kFmt22c,  kFmt21c,  kFmt21c,  kFmt00x,
	};
	
	public static int[] gInstructionIndexTypeTable = new int[]{
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexStringRef,
	    kIndexStringRef,    kIndexTypeRef,      kIndexNone,
	    kIndexNone,         kIndexTypeRef,      kIndexTypeRef,
	    kIndexNone,         kIndexTypeRef,      kIndexTypeRef,
	    kIndexTypeRef,      kIndexTypeRef,      kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexUnknown,
	    kIndexUnknown,      kIndexUnknown,      kIndexUnknown,
	    kIndexUnknown,      kIndexUnknown,      kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexFieldRef,     kIndexFieldRef,
	    kIndexFieldRef,     kIndexFieldRef,     kIndexFieldRef,
	    kIndexFieldRef,     kIndexFieldRef,     kIndexFieldRef,
	    kIndexFieldRef,     kIndexFieldRef,     kIndexFieldRef,
	    kIndexFieldRef,     kIndexFieldRef,     kIndexFieldRef,
	    kIndexFieldRef,     kIndexFieldRef,     kIndexFieldRef,
	    kIndexFieldRef,     kIndexFieldRef,     kIndexFieldRef,
	    kIndexFieldRef,     kIndexFieldRef,     kIndexFieldRef,
	    kIndexFieldRef,     kIndexFieldRef,     kIndexFieldRef,
	    kIndexFieldRef,     kIndexFieldRef,     kIndexMethodRef,
	    kIndexMethodRef,    kIndexMethodRef,    kIndexMethodRef,
	    kIndexMethodRef,    kIndexUnknown,      kIndexMethodRef,
	    kIndexMethodRef,    kIndexMethodRef,    kIndexMethodRef,
	    kIndexMethodRef,    kIndexUnknown,      kIndexUnknown,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexNone,
	    kIndexNone,         kIndexNone,         kIndexFieldRef,
	    kIndexFieldRef,     kIndexFieldRef,     kIndexFieldRef,
	    kIndexFieldRef,     kIndexFieldRef,     kIndexFieldRef,
	    kIndexFieldRef,     kIndexFieldRef,     kIndexUnknown,
	    kIndexVaries,       kIndexInlineMethod, kIndexInlineMethod,
	    kIndexMethodRef,    kIndexNone,         kIndexFieldOffset,
	    kIndexFieldOffset,  kIndexFieldOffset,  kIndexFieldOffset,
	    kIndexFieldOffset,  kIndexFieldOffset,  kIndexVtableOffset,
	    kIndexVtableOffset, kIndexVtableOffset, kIndexVtableOffset,
	    kIndexFieldRef,     kIndexFieldRef,     kIndexFieldRef,
	    kIndexUnknown,
	};
	
	private class DecodedInstruction{
		public long vA = 0;//u4
		public long vB = 0;//u4
		public long vB_wide = 0;//u8
		public long vC = 0;//u4
		public long[] arg = null;//u4[5]
		public int opcode;
		public int indexType;
	}
	
	private class DexFile{
		public String[] strings;
		public String[] types;
		public String[] protos;
		public String[] fields;
		public String[] methods;
		public String[] classs;
	}
	
	public static int kPackedSwitchSignature = 0x100;
	public static int kSparseSwitchSignature = 0x200;
	public static int kArrayDataSignature = 0x300;
	
	DexFile dexfile = null;
	public static String[] opnames = null;
	private List<String> disbytearr = null;
	private byte[] bytecodes = null;
	private byte[] dexfiledata = null;
	public int selectedline = -1;
	
	public DalvikByteCodeModel(File dexfile, Method method, long codeindex){	
		if(method == null)
			return;
		
		opnames = new String[]{
			"nop","move","move/from16","move/16","move-wide","move-wide/from16","move-wide/16","move-object",
			"move-object/from16","move-object/16","move-result","move-result-wide","move-result-object",
			"move-exception","return-void","return","return-wide","return-object","const/4","const/16","const",
			"const/high16","const-wide/16","const-wide/32","const-wide","const-wide/high16","const-string",
			"const-string/jumbo","const-class","monitor-enter","monitor-exit","check-cast","instance-of",
			"array-length","new-instance","new-array","filled-new-array","filled-new-array/range","fill-array-data",
			"throw","goto","goto/16","goto/32","packed-switch","sparse-switch","cmpl-float","cmpg-float","cmpl-double",
			"cmpg-double","cmp-long","if-eq","if-ne","if-lt","if-ge","if-gt","if-le","if-eqz","if-nez","if-ltz",
			"if-gez","if-gtz","if-lez","unused-3e","unused-3f","unused-40","unused-41","unused-42","unused-43","aget",
			"aget-wide","aget-object","aget-boolean","aget-byte","aget-char","aget-short","aput","aput-wide",
			"aput-object","aput-boolean","aput-byte","aput-char","aput-short","iget","iget-wide","iget-object",
			"iget-boolean","iget-byte","iget-char","iget-short","iput","iput-wide","iput-object","iput-boolean",
			"iput-byte","iput-char","iput-short","sget","sget-wide","sget-object","sget-boolean","sget-byte",
			"sget-char","sget-short","sput","sput-wide","sput-object","sput-boolean","sput-byte","sput-char",
			"sput-short","invoke-virtual","invoke-super","invoke-direct","invoke-static","invoke-interface",
			"unused-73","invoke-virtual/range","invoke-super/range","invoke-direct/range","invoke-static/range",
			"invoke-interface/range","unused-79","unused-7a","neg-int","not-int","neg-long","not-long","neg-float",
			"neg-double","int-to-long","int-to-float","int-to-double","long-to-int","long-to-float","long-to-double",
			"float-to-int","float-to-long","float-to-double","double-to-int","double-to-long","double-to-float",
			"int-to-byte","int-to-char","int-to-short","add-int","sub-int","mul-int","div-int","rem-int","and-int",
			"or-int","xor-int","shl-int","shr-int","ushr-int","add-long","sub-long","mul-long","div-long","rem-long",
			"and-long","or-long","xor-long","shl-long","shr-long","ushr-long","add-float","sub-float","mul-float",
			"div-float","rem-float","add-double","sub-double","mul-double","div-double","rem-double","add-int/2addr",
			"sub-int/2addr","mul-int/2addr","div-int/2addr","rem-int/2addr","and-int/2addr","or-int/2addr",
			"xor-int/2addr","shl-int/2addr","shr-int/2addr","ushr-int/2addr","add-long/2addr","sub-long/2addr",
			"mul-long/2addr","div-long/2addr","rem-long/2addr","and-long/2addr","or-long/2addr","xor-long/2addr",
			"shl-long/2addr","shr-long/2addr","ushr-long/2addr","add-float/2addr","sub-float/2addr","mul-float/2addr",
			"div-float/2addr","rem-float/2addr","add-double/2addr","sub-double/2addr","mul-double/2addr",
			"div-double/2addr","rem-double/2addr","add-int/lit16","rsub-int","mul-int/lit16","div-int/lit16",
			"rem-int/lit16","and-int/lit16","or-int/lit16","xor-int/lit16","add-int/lit8","rsub-int/lit8",
			"mul-int/lit8","div-int/lit8","rem-int/lit8","and-int/lit8","or-int/lit8","xor-int/lit8","shl-int/lit8",
			"shr-int/lit8","ushr-int/lit8","+iget-volatile","+iput-volatile","+sget-volatile","+sput-volatile",
			"+iget-object-volatile","+iget-wide-volatile","+iput-wide-volatile","+sget-wide-volatile",
			"+sput-wide-volatile","^breakpoint","^throw-verification-error","+execute-inline","+execute-inline/range",
			"+invoke-object-init/range","+return-void-barrier","+iget-quick","+iget-wide-quick","+iget-object-quick",
			"+iput-quick","+iput-wide-quick","+iput-object-quick","+invoke-virtual-quick","+invoke-virtual-quick/range",
			"+invoke-super-quick","+invoke-super-quick/range","+iput-object-volatile","+sget-object-volatile",
			"+sput-object-volatile","unused-ff",
		};
		
		try{
			this.bytecodes = method.bytecodes();
			if(dexfile != null)
			{
				FileInputStream fi = new FileInputStream(dexfile);
				this.dexfiledata = new byte[(int) dexfile.length()];
				fi.read(this.dexfiledata);
				fi.close();
				parseDex();
			}
			if(bytecodes != null)
				buildDisByte(codeindex);
		}
		catch(Exception e){
			return;
		}
	}
	
	int dexOpcodeFromCodeUnit(int codeUnit){
		int lowByte = codeUnit&0xff;
		if(lowByte != 0xff){
			return lowByte;
		}
		else{
			return ((codeUnit >> 8) | 0x100);
		}
	}
	
	int get1LE(byte[] base, int offset){
		return (base[offset]&0xff);
	}
	
	int get2LE(byte b1, byte b2){
		return ((b1&0xff) | ((b2&0xff) << 8))&0xffff;
	}
	
	int get2LE(byte[] base, int offset){
		return ((base[offset]&0xff) | ((base[offset + 1]&0xff) << 8));
	}
	
	long get4LE(byte b1, byte b2, byte b3, byte b4){
		return ((b1&0xff) | ((b2&0xff) << 8) | ((b3&0xff) << 16) | ((b4&0xff) << 24))&0xffffffffL;
	}
	
	int get4LE(byte[] base, int offset){
		return ((base[offset]&0xff) | ((base[offset + 1]&0xff) << 8) | 
				((base[offset + 2]&0xff) << 16) | ((base[offset + 3]&0xff) << 24));
	}
	
	long get8LE(byte b1, byte b2, byte b3, byte b4, byte b5, byte b6, byte b7, byte b8){
		return ((b1&0xff) | ((b2&0xff) << 8) | ((b3&0xff) << 16) | ((b4&0xff) << 24) |
				((b5&0xff) <<32) | ((b6&0xff) << 40) | ((b7&0xff) << 48) | ((b8&0xff) << 56))&0xffffffffffffffffL;
	}
	
	private class FieldMethodInfo {
	    public String classDescriptor = null;
	    public String name = null;
	    public String signature = null;
	};
	
	public void parseDex() throws UnsupportedEncodingException{
		//parse header
		DexFile tmp = new DexFile();
		int dexoff = 0;	
		if(dexfiledata[0] == 'd' && dexfiledata[1] == 'e' && dexfiledata[2] == 'x')
			dexoff = 0;
		else if(dexfiledata[0] == 'd' && dexfiledata[1] == 'e' && dexfiledata[2] == 'y')
			dexoff = 0x28;
		else
			return;
		int string_ids_size = get4LE(dexfiledata, dexoff + 0x38);
		int string_ids_off = get4LE(dexfiledata, dexoff + 0x3C);
		int type_ids_size = get4LE(dexfiledata, dexoff + 0x40);
		int type_ids_off = get4LE(dexfiledata, dexoff + 0x44);
		int proto_ids_size = get4LE(dexfiledata, dexoff + 0x48);
		int proto_ids_off = get4LE(dexfiledata, dexoff + 0x4C);
		int field_ids_size = get4LE(dexfiledata, dexoff + 0x50);
		int field_ids_off = get4LE(dexfiledata, dexoff + 0x54);
		int method_ids_size = get4LE(dexfiledata, dexoff + 0x58);
		int method_ids_off = get4LE(dexfiledata, dexoff + 0x5C);
		int class_defs_size = get4LE(dexfiledata, dexoff + 0x60);
		int class_defs_off = get4LE(dexfiledata, dexoff + 0x64);
		tmp.strings = new String[string_ids_size];
		tmp.types = new String[type_ids_size];
		tmp.protos = new String[proto_ids_size];
		tmp.fields = new String[field_ids_size];
		tmp.methods = new String[method_ids_size];
		tmp.classs = new String[class_defs_size];
				
		int i;
		//parse string pool
		for(i = 0;i < string_ids_size;i++){
			int dataoff = get4LE(dexfiledata, dexoff + string_ids_off + 4*i);
			int begin = dexoff + dataoff + 1;
			int len = get1LE(dexfiledata, dexoff + dataoff);
			if((len&0x80) != 0){//处理常见情况，长度<32768
				len = (len&0x7f) + get2LE(dexfiledata, dexoff + dataoff + 1);
				begin++;
			}
			tmp.strings[i] = new String(dexfiledata, begin, len,"utf-8");
		}
		//parse typeid
		for(i = 0;i < type_ids_size;i++){
			int descriindex = get4LE(dexfiledata, dexoff + type_ids_off + 4*i);
			tmp.types[i] = tmp.strings[descriindex];
		}
		//parse protoid
		for(i = 0;i < proto_ids_size;i++){
			int return_type_idx = get4LE(dexfiledata, dexoff + proto_ids_off + 12*i + 4);
			int parameters_off = get4LE(dexfiledata, dexoff + proto_ids_off + 12*i + 8);
			String proto = "(";
			if(parameters_off != 0){
				int paramnum = get4LE(dexfiledata, dexoff + parameters_off);
				for(int j = 0;j < paramnum;j++){
					int paramid = get2LE(dexfiledata, dexoff + parameters_off + 4 + 2*j);
					proto += tmp.types[paramid] + ",";
				}
			}
			proto += ")";
			tmp.protos[i] = proto;
		}
		//parse fieldid
		for(i = 0;i < field_ids_size;i++){
			int class_idx = get2LE(dexfiledata, dexoff + field_ids_off + 8*i);
			int type_idx = get2LE(dexfiledata, dexoff + field_ids_off + 8*i + 2);
			int name_idx = get4LE(dexfiledata, dexoff + field_ids_off + 8*i + 4);
			tmp.fields[i] = tmp.types[class_idx] + "->" + tmp.strings[name_idx];
		}
		//parse method
		for(i = 0;i < method_ids_size;i++){
			int class_idx = get2LE(dexfiledata, dexoff + method_ids_off + 8*i);
			int proto_idx = get2LE(dexfiledata, dexoff + method_ids_off + 8*i + 2);
			int name_idx = get4LE(dexfiledata, dexoff + method_ids_off + 8*i + 4);
			tmp.methods[i] = tmp.types[class_idx] + "=>" + tmp.strings[name_idx] + tmp.protos[proto_idx];
		}
		dexfile = tmp;
	}
	
	String getClassDescriptor(int classid){
		if(dexfile != null && classid < dexfile.types.length)
			return dexfile.types[classid];
		else
			return "unknown";
	}
	
	String dexStringById(int stringid){
		if(dexfile != null && stringid < dexfile.strings.length)
			return dexfile.strings[stringid];
		else
			return "unknown";
	}
	
	String getMethodInfo(int methodid){
		if(dexfile != null && methodid < dexfile.methods.length)
			return dexfile.methods[methodid];
		else
			return "unknown";
	}
	
	String getFieldInfo(int fieldid){
		if(dexfile != null && fieldid < dexfile.fields.length)
			return dexfile.fields[fieldid];
		else
			return "unknown";
	}
	
	String indexString(DecodedInstruction decInsn){
		long index;
		long width;
		switch(gInstructionFormatTable[decInsn.opcode&0xff]){
	    case kFmt20bc:
	    case kFmt21c:
	    case kFmt35c:
	    case kFmt35ms:
	    case kFmt3rc:
	    case kFmt3rms:
	    case kFmt35mi:
	    case kFmt3rmi:
	        index = decInsn.vB;
	        width = 4;
	        break;
	    case kFmt31c:
	        index = decInsn.vB;
	        width = 8;
	        break;
	    case kFmt22c:
	    case kFmt22cs:
	        index = decInsn.vC;
	        width = 4;
	        break;
	    default:
	        index = 0;
	        width = 4;
	        break;		
		}
		
		switch(decInsn.indexType){
		case kIndexUnknown:
			return "<unknown-index>";
		case kIndexNone:
			return "<no-index>";
		case kIndexVaries:
			return "<index-varies>";
		case kIndexTypeRef:
			return "type:" + getClassDescriptor((int)index);
		case kIndexStringRef:
			return "string:" + dexStringById((int)index);
		case kIndexMethodRef:{
			return String.format("method %s", getMethodInfo((int)index));
			}
		case kIndexFieldRef:{
			return String.format("field %s", getFieldInfo((int)index));		
		}
		case kIndexInlineMethod:
			return String.format("[inline %0x]", index);
		case kIndexVtableOffset:
			return String.format("[vtable %0x]", index);
		case kIndexFieldOffset:
			return String.format("[obj+%x]", index);
		default:
			return "?";
		}
	}
	
	public void buildDisByte(long codeindex){
		disbytearr = new ArrayList<String>();
		for(int i = 0;i < bytecodes.length;){
			if(selectedline != -1 && i >= codeindex)
				selectedline = disbytearr.size();
			String instructstr = String.format("%04x\t", i);
			long insnWidth = 1;
			int instr = get2LE(bytecodes[i], bytecodes[i + 1]);
			int opcode = dexOpcodeFromCodeUnit(instr);
			if(opcode == opcode_nopcode){
				if(instr == kPackedSwitchSignature){
					insnWidth = 4 + get2LE(bytecodes[i + 2], bytecodes[i + 3])*2;
					instructstr += String.format("packed-switch-data (%d units)", insnWidth);
				}
				else if(instr == kSparseSwitchSignature){
					insnWidth = 2 + get2LE(bytecodes[i + 2], bytecodes[i + 3])*4;
					instructstr += String.format("sparse-switch-data (%d units)", insnWidth);
				}
				else if(instr == kArrayDataSignature){
					int width = get2LE(bytecodes[i + 2], bytecodes[i + 3]);
					long size = get4LE(bytecodes[i + 4], bytecodes[i + 5], bytecodes[i + 6], bytecodes[i + 7]);
					insnWidth = 4 + ((size * width) + 1) / 2;
					instructstr += String.format("array-data (%d units)", insnWidth);
				}
				else{	
					instructstr += String.format("nop //spacer", insnWidth);
				}
			}
			else{
				insnWidth = gInstructionWidthTable[opcode&0xff];
				if(insnWidth == 0)//error
					break;
				instructstr += opnames[opcode];
			}
			
			int format = gInstructionFormatTable[opcode&0xff];
			DecodedInstruction decInsn = new DecodedInstruction();
			decInsn.opcode = opcode;
			decInsn.indexType = gInstructionIndexTypeTable[opcode&0xff];
			if(format == kFmt10x){
				// op
				decInsn.vA = instr >> 8;
			}
			else if(format == kFmt12x){
				// op vA, vB
				decInsn.vA = (instr >> 8)&0x0f;
				decInsn.vB = instr >> 12;
				instructstr += String.format(" v%d, v%d", decInsn.vA, decInsn.vB);
			}
			else if(format == kFmt11n){
				// op vA, #+B
				decInsn.vA = (instr >> 8)&0x0f;
				decInsn.vB = instr >> 12;
				if((decInsn.vB&0x08) != 0)
					decInsn.vB -= 0x10;
				instructstr += String.format(" v%d, #int %d // #%x", decInsn.vA, decInsn.vB, (instr >> 12)&0xff);
			}
			else if(format == kFmt11x){
				// op vAA
				decInsn.vA = instr >> 8;
				instructstr += String.format(" v%d", decInsn.vA);
			}
			else if(format == kFmt10t){
				// op +AA
				decInsn.vA = instr >> 8;
				if((decInsn.vA&0x80) != 0)
					decInsn.vA -= 0x100;
				instructstr += String.format(" %04x // %c%04x", decInsn.vA, (decInsn.vA<0)?'-':'+',(decInsn.vA<0)?-decInsn.vA:decInsn.vA);
			}
			else if(format == kFmt20t){
				// op +AAAA
				decInsn.vA = get2LE(bytecodes[i + 2], bytecodes[i + 3]);	
				if((decInsn.vA&0x8000) != 0)
					decInsn.vA -= 0x10000;
				instructstr += String.format(" %04x // %c%04x", decInsn.vA, (decInsn.vA<0)?'-':'+',(decInsn.vA<0)?-decInsn.vA:decInsn.vA);
			}
			else if(format == kFmt20bc || format == kFmt21c || format == kFmt22x){
				// [opt] op AA, thing@BBBB
				// op vAA, thing@BBBB
				// op vAA, vBBBB
				decInsn.vA = instr >> 8;
				decInsn.vB = get2LE(bytecodes[i + 2], bytecodes[i + 3]);
				if(format == kFmt20bc){
					instructstr += String.format(" v%d, %s", decInsn.vA, indexString(decInsn));	
				}
				else if(format == kFmt21c){
					instructstr += String.format(" v%d, %s", decInsn.vA, indexString(decInsn));	
				}
				else if(format == kFmt22x){
					instructstr += String.format(" v%d, v%d", decInsn.vA, decInsn.vB);
				}
			}
			else if(format == kFmt21s || format == kFmt21t){
				// op vAA, #+BBBB
				// op vAA, +BBBB
				decInsn.vA = instr >> 8;
				decInsn.vB = get2LE(bytecodes[i + 2], bytecodes[i + 3]);	
				if((decInsn.vB&0x8000) != 0)
					decInsn.vB -= 0x10000;
				if(format == kFmt21s){
					instructstr += String.format(" v%d, #int %d // #%x", decInsn.vA, decInsn.vB, decInsn.vB&0xffff);
				}
				else if(format == kFmt21t){
					instructstr += String.format(" v%d, %04x // %c%04x", decInsn.vA, 
						decInsn.vB, (decInsn.vB<0)?'-':'+',(decInsn.vB<0)?-decInsn.vB:decInsn.vB);
				}
			}
			else if(format == kFmt21h){
				// op vAA, #+BBBB0000[00000000]
				decInsn.vA = instr >> 8;
				decInsn.vB = get2LE(bytecodes[i + 2], bytecodes[i + 3]);
				if(opcode == opcode_const_high16){
					long value = decInsn.vB << 16;
					if((value&0x80000000) != 0)
						value -= 0x100000000L;
					instructstr += String.format(" v%d, #int %d // #%x", decInsn.vA, value, decInsn.vB&0xffff);
				}
				else{
					long value = decInsn.vB << 48;
					instructstr += String.format(" v%d, #int %d // #%x", decInsn.vA, value, decInsn.vB&0xffff);	
				}
			}
			else if(format == kFmt23x){
				// op vAA, vBB, vCC
				decInsn.vA = instr >> 8;
				decInsn.vB = bytecodes[i + 2]&0xff;
				decInsn.vC = bytecodes[i + 3]&0xff;
				instructstr += String.format(" v%d, v%d, v%d", decInsn.vA, decInsn.vB, decInsn.vC);
			}
			else if(format == kFmt22b){
				// op vAA, vBB, #+CC
				decInsn.vA = instr >> 8;
				decInsn.vB = bytecodes[i + 2]&0xff;
				decInsn.vC = bytecodes[i + 3];
				instructstr += String.format(" v%d, v%d, #int %d // #%02x", decInsn.vA, decInsn.vB, decInsn.vC, decInsn.vC&0xff);
			}			
			else if(format == kFmt22s || format == kFmt22t){
				// op vA, vB, #+CCCC
				// op vA, vB, +CCCC
				decInsn.vA = (instr >> 8)&0x0f;
				decInsn.vB = instr >> 12;
				decInsn.vC = get2LE(bytecodes[i + 2], bytecodes[i + 3]);
				if((decInsn.vC&0x8000) != 0)
					decInsn.vC -= 0x10000;
				if(format == kFmt22t){
					instructstr += String.format(" v%d, v%d, %04x // %c%04x", decInsn.vA, decInsn.vB, decInsn.vC,
						(decInsn.vC<0)?'-':'+', (decInsn.vC<0)?-decInsn.vC:decInsn.vC);
				}
				else if(format == kFmt22s){
					instructstr += String.format(" v%d, v%d, #int %d // #%04x", decInsn.vA, decInsn.vB, decInsn.vC, decInsn.vC&0xffff);		
				}
			}
			else if(format == kFmt22c || format == kFmt22cs){
				// op vA, vB, thing@CCCC
				// [opt] op vA, vB, field offset CCCC
				decInsn.vA = (instr >> 8)&0x0f;
				decInsn.vB = instr >> 12;
				decInsn.vC = get2LE(bytecodes[i + 2], bytecodes[i + 3]);
				instructstr += String.format(" v%d, v%d, %s", decInsn.vA, decInsn.vB, indexString(decInsn));
			}
			else if(format == kFmt30t){
				// op +AAAAAAAA
				decInsn.vA = get4LE(bytecodes[i + 2], bytecodes[i + 3], bytecodes[i + 4], bytecodes[i + 5]);
				instructstr += String.format(" #%08x", decInsn.vA);
			}
			else if(format == kFmt31t || format == kFmt31c){
				// op vAA, +BBBBBBBB
				// op vAA, string@BBBBBBBB
				decInsn.vA = instr >> 8;
				decInsn.vB = get4LE(bytecodes[i + 2], bytecodes[i + 3], bytecodes[i + 4], bytecodes[i + 5]);		
				if(format == kFmt31c)
					instructstr += String.format(" v%d, %s", decInsn.vA, indexString(decInsn));
				else if(format == kFmt31t){
					instructstr += String.format(" v%d, +%08x ", decInsn.vA, decInsn.vB);
				}
			}
			else if(format == kFmt32x){
				// op vAAAA, vBBBB
				decInsn.vA = get2LE(bytecodes[i + 2], bytecodes[i + 3]);
				decInsn.vB = get2LE(bytecodes[i + 4], bytecodes[i + 5]);	
				instructstr += String.format(" v%d, v%d", decInsn.vA, decInsn.vB);
			}
			else if(format == kFmt31i){
				// op vAA, #+BBBBBBBB
				decInsn.vA = instr >> 8;
				decInsn.vB = get4LE(bytecodes[i + 2], bytecodes[i + 3], bytecodes[i + 4], bytecodes[i + 5]);
				instructstr += String.format(" v%d, #float %f", decInsn.vA, Float.intBitsToFloat((int) decInsn.vB));
			}
			else if(format == kFmt35c || format == kFmt35ms || format == kFmt35mi){
				// op {vC, vD, vE, vF, vG}, thing@BBBB
				// [opt] invoke-virtual+super
				// [opt] inline invoke
				decInsn.vA = instr >> 12;
				decInsn.vB = get2LE(bytecodes[i + 2], bytecodes[i + 3]);
				int regList = get2LE(bytecodes[i + 4], bytecodes[i + 5]);
				if(decInsn.vA == 5){
					if(format == kFmt35mi)//error
						break;
					decInsn.arg = new long[5];
					decInsn.arg[4] = (instr >> 8)&0x0f;
					decInsn.arg[3] = (regList >> 12)&0x0f;
					decInsn.arg[2] = (regList >> 8)&0x0f;
					decInsn.arg[1] = (regList >> 4)&0x0f;
					decInsn.arg[0] = regList&0x0f;
					decInsn.vC = decInsn.arg[0];
				}
				else if(decInsn.vA == 4){
					decInsn.arg = new long[4];
					decInsn.arg[3] = (regList >> 12)&0x0f;
					decInsn.arg[2] = (regList >> 8)&0x0f;
					decInsn.arg[1] = (regList >> 4)&0x0f;
					decInsn.arg[0] = regList&0x0f;
					decInsn.vC = decInsn.arg[0];
				}
				else if(decInsn.vA == 3){
					decInsn.arg = new long[3];
					decInsn.arg[2] = (regList >> 8)&0x0f;
					decInsn.arg[1] = (regList >> 4)&0x0f;
					decInsn.arg[0] = regList&0x0f;
					decInsn.vC = decInsn.arg[0];
				}
				else if(decInsn.vA == 2){
					decInsn.arg = new long[2];
					decInsn.arg[1] = (regList >> 4)&0x0f;
					decInsn.arg[0] = regList&0x0f;
					decInsn.vC = decInsn.arg[0];
				}
				else if(decInsn.vA == 1){
					decInsn.arg = new long[1];
					decInsn.arg[0] = regList&0x0f;
					decInsn.vC = decInsn.arg[0];
				}
				else if(decInsn.vA == 0){	
				}
				else{//error
					break;
				}
				
				instructstr += " {";
				for(int j = 0;j < decInsn.vA;j++){
					instructstr += String.format("v%d ", decInsn.arg[i]);
				}
				instructstr += "}, " + indexString(decInsn);
			}
			else if(format == kFmt3rc || format == kFmt3rms || format == kFmt3rmi){
				// op {vCCCC .. v(CCCC+AA-1)}, meth@BBBB
				// [opt] invoke-virtual+super/range
				// [opt] execute-inline/range
				decInsn.vA = instr >> 8;
				decInsn.vB = get2LE(bytecodes[i + 2], bytecodes[i + 3]);
				decInsn.vC = get2LE(bytecodes[i + 4], bytecodes[i + 5]);
				
				instructstr += " {";
				for(int j = 0;j < decInsn.vA;j++){
					instructstr += String.format("v%d ", decInsn.vC + i);
				}
				instructstr += "}, " + indexString(decInsn);
			}
			else if(format == kFmt51l){
				// op vAA, #+BBBBBBBBBBBBBBBB
				decInsn.vA = instr >> 8;
				decInsn.vB_wide = get8LE(bytecodes[i + 2], bytecodes[i + 3], bytecodes[i + 3],
					bytecodes[i + 4], bytecodes[i + 5], bytecodes[i + 6], bytecodes[i + 7], bytecodes[i + 8])&0xFFFFFFFFFFFFFFFFL;
				instructstr += String.format(" v%d, #float %f", decInsn.vA, Double.longBitsToDouble(decInsn.vB));
			}
			else if(format == kFmt00x){
				
			}
			else{//error
				break;
			}
			
			i += insnWidth * 2;
			disbytearr.add(instructstr);
		}
	}

	@Override
	public Object getElementAt(int index) {
		if(disbytearr != null){
			return new SourceModel.Line(disbytearr.get(index));
		}
		return null;
	}

	@Override
	public int getSize() {
		if(disbytearr != null){
			return disbytearr.size();
		}
		return 0;
	}
}
