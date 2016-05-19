package security.tool;

import java.util.Arrays;

public class Byte_Connect {

	
	public static byte[] connect(byte[] first, byte[] second){
		byte[] NewArray= Arrays.copyOf(first, first.length + second.length);
		System.arraycopy(second, 0, NewArray, first.length, second.length);
		return NewArray;
	}
}
