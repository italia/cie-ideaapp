/**
classe di supporto per l'implementazione degli algoritimi crittografici, più
metodi di utilità
**/

public class Algoritmi {
	
	
	//metodi di supporto per la generazione del canale sicuro
	public static byte[] macEnc(byte[] masterKey,byte[] data) throws Exception{
		byte[] k1 = new byte[8];
		byte[] k2 = new byte[8];
		byte[] k3 = new byte[8];
		System.arraycopy(masterKey, 0, k1, 0, 8);
		System.arraycopy(masterKey, masterKey.length >=16 ? 8 : 0, k2, 0, 8);
		System.arraycopy(masterKey, masterKey.length >=24 ? 16 : 0, k3, 0, 8);
		byte[] mid1 = desEnc(k1,data);//40byte
		//System.out.println("mid1: " + bytesToHex(mid1));
		byte[] mid2 = desDec(k2, getSub(mid1,mid1.length-8,8));//8byte
		//System.out.println("mid2: " +bytesToHex( mid2));
		byte[] mid3 = desEnc(k3, getSub(mid2,0,8));//8byte
		//System.out.println("mid3: " +bytesToHex( mid2));
		return mid3;
	}
	
	
	public static byte[] desEnc(byte[] masterKey,byte[] data) throws Exception{
		byte[] key24 =  new byte[24];;
		if (masterKey.length == 8) {
			System.arraycopy(masterKey, 0, key24, 0, 8);
			System.arraycopy(masterKey, 0, key24, 8, 8);
			System.arraycopy(masterKey, 0, key24, 16, 8);
		}else if (masterKey.length == 16) {
		    System.arraycopy(masterKey, 0, key24, 0, 16);
		    System.arraycopy(masterKey, 0, key24, 16, 8);
		} else {
		    key24 = masterKey;
		}
		
		final SecretKey key = new SecretKeySpec(key24, "TripleDES");
    	final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
    	final Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
    	cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    	byte[] cipherText = cipher.doFinal(data);
    	return cipherText;
	}
	
	public static  byte[] desDec(byte[] masterKey,byte[] data) throws Exception{
		byte[] key24 =  new byte[24];;
		if (masterKey.length == 8) {
			System.arraycopy(masterKey, 0, key24, 0, 8);
			System.arraycopy(masterKey, 0, key24, 8, 8);
			System.arraycopy(masterKey, 0, key24, 16, 8);
		}else if (masterKey.length == 16) {
		    System.arraycopy(masterKey, 0, key24, 0, 16);
		    System.arraycopy(masterKey, 0, key24, 16, 8);
		} else {
		    key24 = masterKey;
		}
		final SecretKey key = new SecretKeySpec(key24, "TripleDES");
    	final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
    	final Cipher decipher = Cipher.getInstance("DESede/CBC/NoPadding");
    	decipher.init(Cipher.DECRYPT_MODE, key, iv);

    	final byte[] result = decipher.doFinal(data);

    	return result;
	}
	
	public static byte[] getSub(byte[] array, int start,int num)throws Exception{
		byte[] data = new byte[num];
		System.arraycopy(array, start, data, 0, data.length);
		return data;
	}
	public static String bytesToHex (byte[] bytes)throws Exception {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (int i=0; i< bytes.length; i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
                
        return sb.toString();
    }

}