package security.tool;

import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Set;

import com.sun.org.apache.bcel.internal.util.ByteSequence;

import sun.applet.resources.MsgAppletViewer;
import sun.security.util.Length;

public class Message {

	
	//4 byte int ��ʾinfo
	int flag;
	//��һ��byte��ʾ��������0��ʾע�ᣬ1��ʾ��¼��2��ʾsend message�� 3 ��ʾ send �ļ�,4��ʾ�Ӻ���,5��ʾ�Ӻ��Ѿܾ�
	//�ڶ�������byte��ʾ����byte��
	//���ĸ�byte��ʾ�Ƿ������һ��message
	int fromid;
	//�ð�ϵ�еĵڼ�����
	int offset;
	int toid;	
	byte[] message;
	
	//func message ������
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
