package com.sun.tools.debug.gui;

public class IntUtils {
	public static int byteToInt(byte b1,byte b2){
		return ((b1&0xff) << 8) + (b2 & 0xff);
	}
	
	public static int byteToInt(byte b1, byte b2, byte b3, byte b4){
		return ((b1&0xff) << 24) + ((b2&0xff) << 16) + ((b3&0xff) << 8) + (b4&0xff);
	}
	
	public static int byteToInt(byte b1, byte b2, byte b3, byte b4, byte b5, byte b6, byte b7, byte b8){
		return ((b1&0xff) << 56) + ((b2&0xff) << 48) +((b3&0xff) << 40) + ((b4&0xff) << 32) + 
				((b5&0xff) << 24) + ((b6&0xff) << 16) + ((b7&0xff) << 8) + (b8&0xff);
	}
}
