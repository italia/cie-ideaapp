package it.ipzs.nfccardreader.logica;

/** Eac.java è la classe che effettua la lettura dei dati MRTD dal microprocessore **/

public class Eac {
	
	private IsoDep isoDep = null;
	static byte[] kSessEnc = null;
	static byte[] kSessMac = null;
	static byte[] seq = null;
	public static Mrz mrz = null;
	public List<Byte> dgList = new ArrayList<Byte>();
	public byte[] efSod = null;
	public byte[] efCVCA = null;
	public byte[] efCom = null;
	public static  Map<Integer, byte[]> mappaDg = null;
	private int index = 0;
	private static final String TAG = "m.recupero";
	
	
	//costruttore
	public Eac(IsoDep isoDep){
		this.isoDep = isoDep;
	}
	

	//metodo iniziale per lo scambio delle chiavi di sessione
	public void init() throws Exception{		
		byte[] apduCmd = AppUtil.hexStringToByteArray("00A4040C07A0000002471001");//select di controllo
		ApduResponse res = new ApduResponse(isoDep.transceive(apduCmd));
		Log.i(TAG,"risposta sw: " + res.getSw());
		Log.i(TAG,"risposta full: " + AppUtil.bytesToHex(res.getResponse()));
		if(res.getSw().equals("9000")){
			Log.i(TAG,"INIT BAC AUTHENTICATION:");
            // init BAC auth
			byte challenge[] = AppUtil.hexStringToByteArray("0084000008");
			ApduResponse apduRes = new ApduResponse(isoDep.transceive(challenge));
			if(!apduRes.getSw().equals("9000")){
				Log.i(TAG,"Errore nella richiesta di challenge [apdu]:0084000008");
                Progressione.testoErrore +=  "Errore nella richiesta di challenge";
				throw new Exception("Errore nella richiesta di challenge [apdu]:0084000008");
			}
			byte[] rndMrtd = apduRes.getResponse();
			
			byte[] birth = null;
			byte[] expire = null;
			if(mrz.getDataNascita().contains("/")){
				//caso in cui viene persa la connessione con il tag nfc ma è stato già fatto il parsing del DG1, in questo caso
				//ho sovrascritto l'mrz...ho cmq i valori delle date yymmgg nel dataString
				birth = mrz.getDataNascitaString().getBytes();
				expire = mrz.getDataScadenzaString().getBytes();
			}
			else{
				birth = mrz.getDataNascita().getBytes();
				expire = mrz.getDataScadenza().getBytes();
			}



			//concateno i dati: numero documento e le due date
			byte[] pn = mrz.getIdCarta().getBytes();
			byte seedPartPn[] = AppUtil.appendByte(pn,AppUtil.checkdigit(pn));
			byte seedPartBirth[] = AppUtil.appendByte(birth, AppUtil.checkdigit(birth));
			byte seedPartExpire[] = AppUtil.appendByte(expire, AppUtil.checkdigit(expire));
			
			byte[] bacSeedData = AppUtil.appendByteArray(seedPartPn, seedPartBirth);
			bacSeedData = AppUtil.appendByteArray(bacSeedData, seedPartExpire);//I00000000666011111512030
			byte[] bacEnc = AppUtil.getLeft(AppUtil.getSha1(AppUtil.appendByteArray(AppUtil.getLeft(AppUtil.getSha1(bacSeedData), 16),new byte[]{(byte)0x00,0x00,0x00,0x01})),16);	
			byte[] bacMac = AppUtil.getLeft(AppUtil.getSha1(AppUtil.appendByteArray(AppUtil.getLeft(AppUtil.getSha1(bacSeedData), 16),new byte[]{(byte)0x00,0x00,0x00,0x02})),16);
			
			//genero i byte[] random
			byte[] rndIs1 = new byte[8];
			AppUtil.getRandomByte(rndIs1);
			
			byte[] kIs = new byte[16];
			AppUtil.getRandomByte(kIs);
			
			byte[] eIs1 = Algoritmi.desEnc(bacEnc, AppUtil.appendByteArray(AppUtil.appendByteArray(rndIs1, rndMrtd), kIs));//32byte
			byte[] eisMac = Algoritmi.macEnc(bacMac, AppUtil.getIsoPad(eIs1));//8byte
			
			//pronto per la mutua auth
			byte apduMutaAuth[] = AppUtil.appendByteArray(eIs1,eisMac);//46byte
			byte[] apduMutuaAutenticazione = AppUtil.appendByte(AppUtil.appendByteArray(AppUtil.appendByteArray(new byte[]{0x00,(byte) 0x82,0x00,0x00,0x28},eIs1),eisMac),(byte)0x28);
			ApduResponse respMutaAuth = new ApduResponse(isoDep.transceive(apduMutuaAutenticazione));//11byte
			if(!respMutaAuth.getSw().equals("9000")){
				Log.i(TAG,"Errore sulla mutua auth BAC " + respMutaAuth.getSw());
                Progressione.testoErrore +=  "Errore durante la procedura di autenticazione BAC! Ripetere la scansione. ";
                //Progressione.erroreBloccante = true;
                throw new Exception("Errore durante la procedura di autenticazione BAC! Ripetere la scansione. " +  respMutaAuth.getSw());
			}


			//
			byte[] kIsMac =  Algoritmi.macEnc(bacMac, AppUtil.getIsoPad(AppUtil.getLeft(respMutaAuth.getResponse(),32)));
			byte[] kIsMac2 = AppUtil.getRight(respMutaAuth.getResponse(),8);
			if(!Arrays.equals(kIsMac,kIsMac2)) {
                Progressione.testoErrore +=  "Errore sulla auth dell'MRTD!!!.";
                //Progressione.erroreBloccante = true;
                throw new Exception("Errore sulla auth dell'MRTD!!!");
            }
			byte[] decResp = Algoritmi.desDec(bacEnc, AppUtil.getLeft(respMutaAuth.getResponse(),32));
			byte[] kMrtd = AppUtil.getRight(decResp,16);
			byte[] kSeed = AppUtil.stringXor(kIs, kMrtd);
			
			//parsing chiavi di sessione
			kSessMac = AppUtil.getLeft(AppUtil.getSha1( AppUtil.appendByteArray(kSeed,new byte[]{0x00,0x00,0x00,0x02})),16);
			kSessEnc = AppUtil.getLeft(AppUtil.getSha1( AppUtil.appendByteArray(kSeed,new byte[]{0x00,0x00,0x00,0x01})),16);
			
			
			byte[] tmp = AppUtil.getSub(decResp, 4, 4);
			byte[] tmp2 = AppUtil.getSub(decResp, 12, 4);
			seq = AppUtil.appendByteArray(tmp,tmp2);
			Log.i(TAG,"END BAC AUTHENTICATION:");

			
		}
		else{
			Log.i(TAG,"protocolla SAC");
		}
	}
	
	
	
	//recupero la struttura dei dg, la conservo dentro una mappa
	public void readDgs()throws Exception{

		Log.i(TAG, "leggo i dg");
		mappaDg = new HashMap<Integer, byte[]>();
		byte[] efCom = leggiDg(30);
		Log.i(TAG, "efcom: => " + AppUtil.bytesToHex(efCom));
		Asn1Tag comtag = Asn1Tag.parse(efCom, false);
		comtag.checkTag(0x60).Child(0, new byte[]{0x5f, 0x01}).verify("0107".getBytes());
		comtag.Child(1, new byte[]{0x5f, 0x36}).verify("040000".getBytes());
		byte[] dhList = comtag.Child(2, (byte) 0x5c).getData();
		for (byte dhNum : dhList) {
			dgList.add(dhNum);
			int dgNum = 0;
			switch (dhNum) {
				case 0x61:
					dgNum = new Integer(1);
					break;
				case 0x75:
					dgNum = new Integer(2);
					break;
				case 0x6b:
					dgNum = new Integer(11);
					break;
				case 0x6e:
					dgNum = new Integer(14);
					break;
				case 0x77:
					dgNum = new Integer(29);
					break;

			}
			if (dgNum != 0)
				mappaDg.put(dgNum, leggiDg(dgNum));
			if(!mappaDg.containsKey(new Integer(29)))
				mappaDg.put(new Integer(29), leggiDg(29));
		}

    }

    public void parseDg1()throws Exception{parseDg(new Integer(1));}
	public void parseDg11()throws Exception{
		if(mappaDg.containsKey(new Integer(11)))
			parseDg(new Integer(11));
		else
		return;
	}
    public void parseDg2()throws Exception{parseDg(new Integer(2));}

	
	
	//metodo per il parsing del dg
	//numDg: il numero del datagroup da fare il parsing
	public void parseDg(int numDg) throws Exception{
		Log.i(TAG,"parse il dg: " + numDg);
		//progress.setProgress(50, "Parsing DG"+ numDg);
		Class tipo = byte[].class;
		byte[] argomenti  = new byte[1];
		argomenti = mappaDg.get(new Integer(numDg));
        if(argomenti == null)
			throw new Exception("Errore durante la procedura di PARSING DG:"+numDg);


		Object classe = Class.forName("it.ipzs.nfccardreader.beanAndUtils.Dg"+numDg).newInstance();
		Method m = classe.getClass().getDeclaredMethod("parse", tipo);
		Object obj = m.invoke(classe, argomenti);
        boolean argomentiDiRitorno = Boolean.parseBoolean(obj.toString());
        Log.i(TAG,"terminato il metodo: " + classe.getClass().getCanonicalName()+" con result: " +  argomentiDiRitorno);




	}
	
	//metodo per la lettura dei dg
	//numDg: il numero del datagroup da leggere
	public byte[] leggiDg(int numDg) throws Exception{
		Log.i(TAG,"Leggo il dg: " + numDg);

		byte[] data = new byte[0];
		byte[] resp = null;
		byte somma = (byte) ((byte) numDg + (byte)0x80);//-126
		String hex = AppUtil.bytesToHex( new byte[]{somma});//82
		byte[] appo = AppUtil.hexStringToByteArray("0cb0" + hex +"0006");//. ToString("X2") + " 00 06")
		byte[] apdu = sm(kSessEnc, kSessMac, appo);// ' read DG 
		ApduResponse respDg = new ApduResponse(isoDep.transceive(apdu));
        if (!respDg.getSw().equals("9000")){
        	Log.i(TAG,"Errore nella selezione del DG" + numDg + " SW: " + respDg.getSw());
            Progressione.testoErrore +=  "Errore nella selezione del DG:" + numDg;
            throw new Exception("Errore nella selezione del DG" + numDg + " SW: " + respDg.getSw());
        }
     
       byte[] chunkLen = respSM(kSessEnc, kSessMac, respDg.getResponse());
       int maxLen=Asn1Tag.parseLength(chunkLen);
       
        while (data.length < maxLen)
        {
            int readLen = Math.min(0xe0, maxLen - data.length);//224
            byte[] appo2 = AppUtil.appendByte(AppUtil.appendByte(AppUtil.appendByte(AppUtil.hexStringToByteArray("0cb0"),(byte) ((byte) (data.length / 256) & (byte)0x7f)),(byte) (data.length & 0xff)),(byte) readLen);
  
            byte[] apduDg = sm(kSessEnc, kSessMac, appo2);
            ApduResponse respDg2 = new ApduResponse(isoDep.transceive(apduDg));// ' read DG
            //int readLen = Math.Min(512, maxLen - data.Size);
            //sw = sc.Transmit(LongSM(KSessEnc, KSessMac, new ByteArray("0c b0 ").Append((byte)(((byte)(data.Size>>8)) & (byte)0x7f)).Append((byte)(data.Size & 0xff)),null,new byte[] { (byte)(readLen >> 8), (byte)(readLen & 0xff) }, seq), ref resp);// ' read DG
            if (!respDg2.getSw().equals("9000")){
            	Log.i(TAG,"Errore nella lettura del DG" + numDg +" codice errore: " + respDg2.getSw());
            	throw new Exception("Errore nella lettura del DG" + numDg +" codice errore: " + respDg2.getSw() );
            }
            byte[] chunk=respSM(kSessEnc, kSessMac, respDg2.getResponse());
            
            data = AppUtil.appendByteArray(data,chunk);


        }
        return data;
		
	}
	
	
	
	
	public  byte[] respSM(byte[] keyEnc, byte[] keySig, byte[] resp) throws Exception {
         return respSM(keyEnc, keySig, resp,  false);
     }

	
	//metodo per la gestione della risposta Secure Message
	public byte[] respSM(byte[] keyEnc, byte[] keySig, byte[] resp, boolean odd) throws Exception{
		
         AppUtil.increment(seq);
         // cerco il tag 87
         setIndex(0);
         byte[] encData = null;
         byte[] encObj = null;
         byte[] dataObj = null;
         do
         {
             if (Byte.compare(resp[index], (byte) 0x99) == 0 )
             {
            	 if (Byte.compare(resp[index+1], (byte) 0x02) != 0 )
                     throw new Exception("Errore nella verifica del SM - lunghezza del DataObject");
                 dataObj = AppUtil.getSub(resp, index, 4);
                 setIndex(index,4);//index += 4;
                 continue;
             }
             if (Byte.compare(resp[index], (byte) 0x8e) == 0 )
             {
            	   byte[] calcMac = Algoritmi.macEnc(keySig, AppUtil.getIsoPad(AppUtil.appendByteArray(AppUtil.appendByteArray(seq,encObj),dataObj)));
                 setIndex(index,1);//index++;
                 if (Byte.compare(resp[index], (byte) 0x08) != 0 )
                     throw new Exception("Errore nella verifica del SM - lunghezza del MAC errata");
                 setIndex(index,1);//index++;
                 if (! Arrays.equals(calcMac,AppUtil.getSub(resp,index, 8)))
                     throw new Exception("Errore nella verifica del SM - MAC non corrispondente");
                 setIndex(index,8);//index += 8;
                 continue;
             }
             if (resp[index] == (byte) 0x87 )
             {
            	 if (unsignedToBytes(resp[index+1]) > unsignedToBytes((byte) 0x80) )
                 {

                     int lgn = 0;
                     int llen = unsignedToBytes(resp[index + 1]) -  0x80;
                     if (llen == 1)
                         lgn = unsignedToBytes(resp[index + 2]);
                     if (llen == 2)
                         lgn = (resp[index + 2] << 8) | resp[index + 3];
                     encObj = AppUtil.getSub(resp,index, llen + lgn + 2);
                     encData = AppUtil.getSub(resp,index + llen + 3, lgn - 1); // ' levo il padding indicator
                     setIndex(index,llen,lgn,2);//index += llen + lgn + 2;
                 }
                 else
                 {
                     encObj = AppUtil.getSub(resp,index, resp[index + 1] + 2);
                     encData = AppUtil.getSub(resp,index + 3, resp[index + 1] - 1); // ' levo il padding indicator
                     setIndex(index,resp[index + 1],2); //index += resp[index + 1] + 2;
                 }
                 continue;
             }

             else
            	 if (Byte.compare(resp[index], (byte) 0x85) == 0 ) 
                 {
            		 if (Byte.compare(resp[index+1], (byte) 0x80) > 0 )
                     {
                         int lgn = 0;
                         int llen = resp[index + 1] - 0x80;
                         if (llen == 1)
                             lgn = resp[index + 2];
                         if (llen == 2)
                             lgn = (resp[index + 2] << 8) | resp[index + 3];
                         encObj = AppUtil.getSub(resp,index, llen + lgn + 2);
                         encData = AppUtil.getSub(resp,index + llen + 2, lgn); // ' levo il padding indicator
                         setIndex(index,llen,lgn,2);//index += llen + lgn + 2;
                     }
                     else
                     {
                         encObj = AppUtil.getSub(resp,index, resp[index + 1] + 2);
                         encData = AppUtil.getSub(resp,index + 2, resp[index + 1]);
                         setIndex(index,resp[index + 1],2); //index += resp[index + 1] + 2;

                     }
                     continue;
                 }
                 else
                     throw new Exception("Tag non previsto nella risposta in SM");
             //index = index + resp[index + 1] + 1;
         }while (index < resp.length);
         if (encData != null){
        	 if(odd){
        		/* byte[] smResp = isoRemove(Algoritmi.desDec(keyEnc, encData));
        		 Asn1Tag tag = Asn1Tag.parse(smResp, false);
        		 return tag.get*/
        		 Log.i(TAG,"caso no previsto");
        	 }
        	 else
                 return isoRemove(Algoritmi.desDec(keyEnc, encData));
         }
         return null;
   }
	
	
	
	public static int unsignedToBytes(byte b) {
	    return b & 0xFF;
	  }
	
     public byte[] isoRemove(byte[] data) throws Exception
     {
         int i;
         for (i = data.length - 1; i >= 0; i--)
         {
             if (data[i] == (byte)0x80)
                 break;
             if (data[i] != 0x00)
                 throw new Exception("Padding ISO non presente");
         }
         return AppUtil.getLeft(data, i);
     }
	
	//metodo che compone l'apdu da mandare alla carta in secure message
	private byte[] sm(byte[] keyEnc, byte[] keyMac, byte[] apdu) throws Exception{
		AppUtil.increment(seq);
		byte[] calcMac = AppUtil.getIsoPad(AppUtil.appendByteArray(seq, AppUtil.getLeft(apdu,4)));
		byte[] smMac;
		byte[] dataField = null;
		byte[] doob;

		if(apdu[4] != 0 && apdu.length > 5){
			//encript la parte di dati
			byte[] enc = Algoritmi.desEnc(keyEnc, AppUtil.getIsoPad(AppUtil.getSub(apdu, 5, apdu[4])));
			if(apdu[1] %2 == 0){
				doob = AppUtil.asn1Tag(AppUtil.appendByteArray(new byte[]{0x001},enc),0x87);
			}
			else
				doob = AppUtil.asn1Tag(enc, 0x85);
			calcMac = AppUtil.appendByteArray(calcMac,doob);
			dataField = AppUtil.appendByteArray(dataField,doob);
        }
        if (apdu.length == 5 || apdu.length == apdu[4] + 6)
        { // ' se c'è un le
            doob = new byte[] {(byte) 0x97,(byte) 0x01, apdu[apdu.length - 1]};
            calcMac = AppUtil.appendByteArray(calcMac,doob);
            if(dataField == null)
            	dataField = doob.clone();
            else
            	dataField = AppUtil.appendByteArray(dataField,doob);
        }

        smMac = Algoritmi.macEnc(keyMac, AppUtil.getIsoPad(calcMac));
        //Log.i(TAG,"smMac: " + bytesToHex(smMac));
        dataField = AppUtil.appendByteArray(dataField, AppUtil.appendByteArray(new byte[] { (byte)0x8e, 0x08 },smMac));
        //Log.i(TAG,"dataField: " + bytesToHex(dataField));
        byte[] finale = AppUtil.appendByte(AppUtil.appendByteArray(AppUtil.appendByteArray(AppUtil.getLeft(apdu, 4),new byte[]{(byte)dataField.length}),dataField),(byte)0x00);
        //Log.i(TAG,"finale: " + bytesToHex(finale));
        return finale;
		
	}



	
	
	
	
	public List<Byte> getDgList() {
		return dgList;
	}
	public void setDgList(List<Byte> dgList) {
		this.dgList = dgList;
	}
	public byte[] getEfSod() {
		return efSod;
	}
	public void setEfSod(byte[] efSod) {
		this.efSod = efSod;
	}
	public byte[] getEfCVCA() {
		return efCVCA;
	}
	public void setEfCVCA(byte[] efCVCA) {
		this.efCVCA = efCVCA;
	}
	public byte[] getEfCom() {
		return efCom;
	}
	public void setEfCom(byte[] efCom) {
		this.efCom = efCom;
	}
	public int getIndex() {
		return index;
	}
	public void setIndex(int... argomenti) {
		int tmpIndex = 0;
		int tmpSegno = 0;
		for(int i=0;i<argomenti.length;i++){
			if(Math.signum(argomenti[i]) < 0){
				tmpSegno = argomenti[i] & 0xFF;
				tmpIndex += tmpSegno;
			}
			else
				tmpIndex += argomenti[i];
			//System.out.print("sommo: " +  tmpIndex+" , ");
		}
		this.index = tmpIndex;
	}

	public static Mrz getMrz() {
		return mrz;
	}

}
