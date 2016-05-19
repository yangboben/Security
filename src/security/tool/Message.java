package security.tool;

import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Set;

import com.sun.org.apache.bcel.internal.util.ByteSequence;

import sun.applet.resources.MsgAppletViewer;
import sun.security.util.Length;

public class Message {

	
	//4 byte int 表示info
	int flag;
	//第一个byte表示命令类型0表示注册，1表示登录，2表示send message， 3 表示 send 文件,4表示加好友,5表示加好友拒绝
	//第二第三个byte表示随后的byte数
	//第四个byte表示是否是最后一个message
	int fromid;
	//该包系列的第几个包
	int offset;
	int toid;	
	byte[] message;
	
	//func message 的类型
	public static void client_send(Message msg,DataOutputStream output) throws IOException{
		 
		output.write(int2bytes(msg.flag));
		output.write(int2bytes(msg.fromid));
		output.write(int2bytes(msg.offset));
		output.write(int2bytes(msg.toid));
		output.write(msg.message);
		
		
	}
	
	public byte getfunc(){
	return (byte)((flag& 0xff000000) >> 24);
	}
	
	public void setfunc(byte func){
		 flag = (flag & 0x00ffffff) | ( ( func&0x000000ff )<<24 & 0xff000000); 
	}
	
	public void setLength(int length){
		flag = (flag & 0xff0000ff) | ( ( length &0x0000ffff )<<8 & 0x00ffff00); 
	}
	
	public int getLength(){
		return (flag & 0x00ffff00) >>8;
	}
	
	public void setEndbyte(){
		flag = (flag & 0xffffff00) | 1; 
	}
	public boolean ifEnd(){
		if((flag & 1)!=0)
			return false;
		else 
			return true;
			 
	} 
	
	private static byte[] int2bytes(int in) {
		ByteBuffer buffer = ByteBuffer.allocate(4); 
		  buffer.putInt(in);
		  return buffer.array();
	}
	
	private static int bytes2int(byte[] in){	
		ByteBuffer buffer = ByteBuffer.allocate(4); 
		  buffer.put(in,0,in.length);
		  buffer.flip();
		  return buffer.getInt();		
	}
}
