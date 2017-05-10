/**
classe di utilità
**/

public class AppUtil {


	public static int toUint(byte[] dataB)throws Exception{
		if(dataB == null)
			return 0;
		int val = +0;
		for (int i =0 ; i < dataB.length; i++)
		{
			val = val << 8 | dataB[i];
		}
		return val;
	}


	public  byte[] PadInt(byte[] value, int size)throws Exception
	{
		byte[] sz =  getRight(value,size);
		if (sz.length < size)
			return appendByteArray(fill(size - sz.length,(byte) 0x00),sz);
		else
			return sz;
	}

	public static byte[] fill(int size, byte content) throws Exception{
		byte[] data=new byte[size];
		for (int i = 0; i < size; i++)
			data[i] = content;
		return data;
	}
	public static  int unsignedToBytes(byte b)throws Exception {
		return b & 0xFF;
	}
	public static  byte unsignedToBytes(int b)throws Exception {
		return (byte) (b & 0xFF);
	}
	static byte[] lenToBytes(int value) throws Exception {
		if (value<0x80) {
			return new byte[] {(byte)value};
		}
		if (value<=0xff) {
			return new byte[] {(byte)0x81,(byte)value};
		}
		else if (value<=0xffff) {
			return new byte[] {(byte)0x82,(byte)(value >> 8),(byte)(value & 0xff)};
		}
		else if (value<=0xffffff) {
			return new byte[] {(byte)0x83,(byte)(value>> 16),(byte)((value>> 8) & 0xff),(byte)(value & 0xff)};
		}
		else if (value<=0xffffffff) {
			return new byte[] {(byte)0x84,(byte)(value>>24),(byte)((value>> 16) & 0xff),(byte)((value>> 8) & 0xff),(byte)(value & 0xff)};
		}
		throw new Exception("dati troppo lunghi");
	}
	public static byte[] asn1Tag(byte[] array,int tag) throws Exception {



		byte[] _tag=  tagToByte(tag);//1

		byte[] _len=lenToBytes(array.length);//2

		byte[] data=new byte[_tag.length+_len.length+array.length];//131

		System.arraycopy(_tag,0,data,0,_tag.length);
		System.arraycopy(_len,0,data,_tag.length,_len.length);
		System.arraycopy(array,0,data,_tag.length+_len.length,array.length);
		return data;
	}


	public static byte[] tagToByte(int value) throws Exception{
		if (value<=0xff) {
			return new byte[] { unsignedToBytes(value)};
		}
		else if (value<=0xffff) {
			return new byte[] {(byte)(value >> 8),(byte)(value & 0xff)};
		}
		else if (value<=0xffffff) {
			return new byte[] {(byte)(value>> 16),(byte)((value>> 8) & 0xff),(byte)(value & 0xff)};
		}
		else if (value<=0xffffffff) {
			return new byte[] {(byte)(value>>24),(byte)((value>> 16) & 0xff),(byte)((value>> 8) & 0xff),(byte)(value & 0xff)};
		}
		throw new Exception("tag troppo lungo");
	}
	public static void increment (byte[] array)throws Exception{increment(array,array.length-1);}

	public static void increment (byte[] array, int indice)throws Exception{
		//System.out.println("seq:  " + bytesToHex(array));
		if (Byte.compare(array[indice],(byte)0xff) == 0){ //Byte.MAX_VALUE) {
			//System.out.println("trovato un max_value ");
			array[indice] = 0x00;//Byte.MIN_VALUE;
			increment(array, (indice - 1));
		}
		else {
			array[indice] = (byte) (array[indice] + 1);
			//System.out.println("m.recupero seq incremantata:  " + bytesToHex(array));
		}
	}


	public static void getStringFromByteArray(byte[] array)throws Exception{
		String str = new String(array, StandardCharsets.UTF_8);
		System.out.println(str);
	}

	public static byte[] getSub(byte[] array, int start,int num)throws Exception{
		if(Math.signum(num) < 0)
			num = num & 0xff;
		byte[] data = new byte[num];
		System.arraycopy(array, start, data, 0, data.length);
		return data;
	}


	public static byte[] getSub(byte[] array, int start)throws Exception{

		byte[] data = new byte[array.length - start];
		System.arraycopy(array, start, data, 0, data.length);
		return data;
	}

	public static byte[] stringXor(byte[] b1, byte[] b2) throws Exception{
		if(b1.length != b2.length)
			throw new Exception("Le due stringhe hanno lunghezza diversa!");
		byte[] data = new byte[b1.length];
		for(int i=0;i<b1.length;i++){
			data[i] = (byte)(b1[i]^b2[i]);
		}
		return data;
	}

	public static byte[] getIsoPad(byte[] data)throws Exception{
		int padLen;
		if((data.length & 0x7) == 0)
			padLen = data.length + 8;
		else
			padLen = data.length - (data.length & 0x7) + 0x08;
		byte[] padData = new byte[padLen];
		System.arraycopy(data, 0, padData, 0, data.length);
		padData[data.length] = (byte)0x80;
		for(int i = data.length + 1; i<padData.length;i++)
			padData[i] = 0;
		return padData;
	}
	public static  byte[] hexStringToByteArray(String s) throws Exception{
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}
	public static void getRandomByte(byte[] array)throws Exception{
		Random r = new Random();
		r.nextBytes(array);
	}

	public static byte[] getSha1(byte[] array) throws  Exception{
		MessageDigest md = MessageDigest.getInstance("SHA1");
		return md.digest(array);
	}
	public static byte[] getRight(byte[] array,int num)throws Exception{
		if(num > array.length)
			return array.clone();
		byte data[] = new byte[num];
		System.arraycopy(array, array.length - num, data, 0, num);
		return data;
	}
	public static byte[] getLeft(byte[] array,int num)throws Exception{
		if(num > array.length)
			return array.clone();
		byte data[] = new byte[num];
		System.arraycopy(array, 0, data, 0, num);
		return data;
	}

	public static byte[] appendByteArray(byte[] a, byte[]b)throws Exception{
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		return c;
	}
	public static byte[] appendByte(byte[] a, byte b)throws Exception{
		byte[] c = new byte[a.length + 1];
		System.arraycopy(a, 0, c, 0, a.length);
		c[a.length] = b;
		return c;
	}
	public static byte checkdigit(byte[] data) throws Exception
	{
		int i;
		int tot = 0;
		int curval = 0;
		int[] weight = new int[] { 7, 3, 1 };
		for (i = 0; i < data.length; i++)
		{
			char ch = Character.toUpperCase(((char)data[i]));
			if (ch >= 'A' && ch <= 'Z')
				curval = ch - 'A' + 10;
			else
			{
				if (ch >= '0' && ch <= '9')
					curval = ch - '0';
				else
				{
					if (ch == '<')
						curval = 0;
					else
						throw new Exception("errore nel calcolo della check digit");
				}
			}
			tot += curval * weight[i % 3];
		}
		tot = tot % 10;
		return (byte)('0' + tot);
	}

	public static  String bytesToHex (byte[] bytes) throws Exception{
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		for (int i=0; i< bytes.length; i++) {
			sb.append(String.format("%02x", bytes[i]));
		}
		return sb.toString();
	}
}