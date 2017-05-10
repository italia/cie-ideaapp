/**

EacListener.java è la classe "ponte" tra l'interfaccia utente e lo strato di logica
che effettua la lettura dei dati dal microprocessore. 
Al suo interno i metodi per gestire la progressione della lettura e la gestione degli errori

**/


public class EacListener implements Runnable {
	
	private Eac eac = null;
	private IsoDep isoDep;
	private MainActivity mainActivity;
	
	//costruttore
	public EacListener(IsoDep isoDep, MainActivity mainActivity) {
		this.isoDep = isoDep;
		this.mainActivity = mainActivity;
	}
	
	
	@Override
	public void run() {//thread
		boolean tagLost =false;
		try {
				//si apre la connessione
				isoDep.connect();
				isoDep.setTimeout(6000);
				eac = new Eac(isoDep);//istanza della class di logica
				eac.init();//scambio di chiavi
				eac.readDgs();//lettura dei datagroups
				eac.parseDg1();//parsing datagroup 1
				eac.parseDg11();//parsing datagroup 11
				eac.parseDg2();//parsing datagroup 2
				isoDep.close();//si chiude la connessione IsoDep
	
			}catch(android.nfc.TagLostException excp){
				//si gestisce la perdita del tag nfc
			}catch (IOException ioexc){
				//gestione eccezioni lanciate durante la lettura
			}
			catch (Exception e) {
				//gestione errori generali
			}

	}

}