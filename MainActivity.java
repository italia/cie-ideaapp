/**

MainActivity.java

Dopo la prima fase che prevede la scansione dell'MRZ (codice riportato sul documento di 90 caratteri
per la CIE e il PSE, 88 caratteri per il Passaporto elettronico) viene chiesto all'utente
di avvicinare il dispositivo al documento in modo da avviare la procedura di lettura dei 
dati dal processore.
La classe Android MainActivity implementa l'interfaccia nativa Java in grado di reagire ad eventi generati 
dal lettore NFC,  NfcAdapter.ReaderCallback. Essa instanzia un oggetto di tipo 
NfcAdapter per l'opportuna  abilitazione alla lettura delle carte di tipo IsoDep A/B: 
nfcAdapter.enableReaderMode(this, this, NfcAdapter.FLAG_READER_NFC_A | 
	NfcAdapter.FLAG_READER_NFC_B |  
	NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null);
	
inoltre la classe preposta implementa il metodo:
public void onTagDiscovered(Tag tag){}
Il metodo riceve in ingresso un oggetto di tipo Tag che contiene tutte le informazioni sul tipo di chip in corso di ispezione.
**/

public class MainActivity extends Activity implements NfcAdapter.ReaderCallback {

	private NfcAdapter nfcAdapter;
	//altre proprietà	.....
	
	@Override
    public void onResume() {
    //sull'onResume dell'activity viene instanziato l'oggetto adapter e viene registrato l'evento
        super.onResume();
		nfcAdapter = NfcAdapter.getDefaultAdapter(this);
		nfcAdapter.enableReaderMode(this, this, NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_NFC_B |  NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null);
	}

	//metodo listener invocato quando si appoggia il documento al terminale
  @Override
    public void onTagDiscovered(Tag tag) {
        String infoTag[] = null;
        try {
            infoTag = getTagInfo(tag);//si recuperano le informazioni del tag 
        }catch(Exception exc){exc.printStackTrace();}
 
        IsoDep isoDep = IsoDep.get(tag);//l'oggetto IsoDep implementa la specifica  ISO-DEP (ISO 14443-4) 
        								// per le operazioni di I/O verso il chip
        								
        //alcuni controlli sul flusso
        if(this.mSelectedId == -2 && Eac.mrz != null) {
        	//se tutto OK, viene avviato il thread che legge i dati
            EacListener eacListener = new EacListener(isoDep, this);
            eacListener.run();
        }else
            messaggio("Prima devi eseguire la scansione dell' MRZ, dopo avvicinare la carta al dispositivo.");

    }
    
    
   
}




