#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sqlite3.h>

// definizione costanti
#define MAX_USER_LENGTH 100
#define MAX_PASSWORD_LENGTH 100
#define MAX_QUERY_LENGTH 200

#define PAGE_BUFFER_LENGTH 4096
#define MAX_POST_DATA 1024

// Debug modes
//#define LOCAL_MODE
//#define DB_DEBUG_MODE
#define NET_DEBUG_MODE


// Strutture per la connessione via OpenSSL
BIO *bio = NULL; // Struttura BIO (OpenSSL)
SSL *ssl = NULL; // Struttura SSL (OpenSSL)
SSL_CTX *ctx = NULL; // OpenSSL Context


// Dati per la richiesta
char univaqLoginHost[] = 
	#ifndef LOCAL_MODE
		"autenticazione.univaq.it:443";
	#else
		"localhost:443";
	#endif

char univaqPostDataTemplate[] = "buttonClicked=4"
								"&redirect_url=autenticazione.univaq.it%%2F"
								"&err_flag=0"
								"&info_flag=0"
								"&info_msg=0"
								"&username=%s"
								"&password=%s";

// Richiesta di prova
char Request_0[] =
	"GET / HTTP/1.1\r\n"
	#ifdef LOCAL_MODE
		"Host: localhost\r\n"
	#else
		"Host: autenticazione.univaq.it\r\n"
	#endif
	"User-Agent: Mozilla/5.0\r\n"
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
	"Accept-Language: en-us,en;q=0.7,it;q=0.3\r\n"
	"Accept-Encoding: gzip, deflate\r\n"
	"DNT: 1\r\n"
	"Connection: keep-alive\r\n\r\n";

// Richiesta GET della pagina con il form per il login
char Request_1[] =
	#ifdef LOCAL_MODE
	"GET /~wtiberti/test/login.php HTTP/1.1\r\n"
	"Host: localhost\r\n"
	#else
	"GET /fs/customwebauth/login.html?switch_url=https://autenticazione.univaq.it/login.html&ap_mac=00:25:84:96:1f:90&wlan=UNIVAQ-HotSpot HTTP/1.1\r\n"
	"Host: autenticazione.univaq.it\r\n"
	#endif
	"User-Agent: Mozilla/5.0\r\n"
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
	"Accept-Language: en-us,en;q=0.7,it;q=0.3\r\n"
	"Accept-Encoding: gzip, deflate\r\n"
	"DNT: 1\r\n"
	"Connection: keep-alive\r\n\r\n";

// Template per l'invio dati POST per il login effettivo
char Request_2[] =
	#ifdef LOCAL_MODE
	"POST /~wtiberti/test/login.php HTTP/1.1\r\n"
	"Host: localhost\r\n"
	#else
	"POST /login.html HTTP/1.1\r\n"
	"Host: autenticazione.univaq.it\r\n"
	#endif
	"User-Agent: Mozilla/5.0\r\n"
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
	"Accept-Language: en-us,en;q=0.7,it;q=0.3\r\n"
	"Accept-Encoding: gzip, deflate\r\n"
	"DNT: 1\r\n"
	#ifndef LOCAL_MODE
	"Referer: https://autenticazione.univaq.it/fs/customwebauth/login.html?"
	"switch_url=https://autenticazione.univaq.it/login.html&ap_mac=00:25:84:96:1f:90"
	"&wlan=UNIVAQ-HotSpot&redirect=autenticazione.univaq.it/\r\n"
	#endif
	"Connection: keep-alive\r\n"
	"Content-Type: application/x-www-form-urlencoded\r\n"
	"Content-Length: %u\r\n\r\n"
 	"%s\r\n\r\n"; // Segnaposto per i dati POST


char elaboredPostData[ MAX_POST_DATA ]; // Richiesta POST elaborata ( a partire dal template )
char pageBuffer[ PAGE_BUFFER_LENGTH ] = { 0 }; // Buffer per la risposta del server

// Buffer per nome utente e password
char nomeUtente[ MAX_USER_LENGTH ] = { 0 };
char passwordUtente[ MAX_PASSWORD_LENGTH ] = { 0 };


// Dati per il database sqlite degli utenti
char nomeDatabase[] = "Users.db";
sqlite3 *connessioneDatabase;
char *outputErrori;


// Query per il database
char query_selezionaPassword[] = "SELECT userPassword FROM UserTable WHERE userName=\"%s\";";
char queryBuffer[ MAX_QUERY_LENGTH ] = { 0 };


// Prototipi di funzione ------------------------------------------------------
int RetrievePassword( const char *name );
int GetPassword( void *nonUsato, int numeroCampi, char **valori, char **nomiColonne );
int SSL_Connect( void );
int ClearStructs( int quali_pulire );

int PreparePostRequest( char *username, char *password );
int SendData( char *dati );
int ReadData( char *buffer, const unsigned long buffer_size );
// ----------------------------------------------------------------------------


int main( int argc, char *argv[] )
{	
	// Verifico il numero di argomenti passati tramite linea di comando
	if( argc != 2 )
	{
		puts( "Uso: UnivaqLogger <nome utente>\n" );
		return 1;
	}
	
	// Connessione al database Sqlite e prelievo password
	if( ! RetrievePassword( argv[1] ) )
	{
		fprintf( stderr, "[ERRORE] Password non reperibile\n" );
		exit( 2 );
	}
	
	// Preparazione richiesta
	if( ! PreparePostRequest( nomeUtente, passwordUtente ) )
	{
		fprintf( stderr, "[ERRORE] Creazione dati POST non riuscita.\n" );
		exit( 3 );
	}
	
	// Inizializzazione OpenSSL
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	SSL_library_init();
	
	// Connessione SSL
	if( ! SSL_Connect() )
		exit( 3 );
	
	// Richieste --------------------------------------------------------------
	
	// test numero #1
	
	/*
	#ifdef NET_DEBUG_MODE
		printf( "\x1B[0;94m%s\x1B[0m", Request_1 );
	#endif
		
	puts( "\x1B[0;92m" );
	SendData( Request_1 );
	while( ReadData( pageBuffer, PAGE_BUFFER_LENGTH-2 ) > 0 )
	{
		pageBuffer[ PAGE_BUFFER_LENGTH-1 ] = 0;
		puts( pageBuffer );
		fflush( stdout );
	}
	puts( "\x1B[0m" );
	*/
	
	#ifdef NET_DEBUG_MODE
		printf( "\x1B[0;94m%s\x1B[0m", elaboredPostData );
	#endif
	
	puts( "\x1B[0;92m" );
	SendData( elaboredPostData );
	while( ReadData( pageBuffer, PAGE_BUFFER_LENGTH-2 ) > 0 )
	{
		pageBuffer[PAGE_BUFFER_LENGTH-1] = 0;
		puts( pageBuffer );
		fflush( stdout );
	}
	puts( "\x1B[0m" );

	
	// Chiusura ---------------------------------------------------------------
	ClearStructs( 3 );
	return 0;
}

// Funzione di callback per la query relativa alla password  ( -> SQLite )
int GetPassword( void *nonUsato, int numeroCampi, char **valori, char **nomiColonne )
{
	if( numeroCampi == 1 )
	{
		#ifdef DB_DEBUG_MODE
		printf( "[DEBUG] Campi: %d\n", numeroCampi );
		for( int i=0; i<numeroCampi; i++ )
			printf( "nome colonna %d: %s\n", i, nomiColonne[i] );
		for( int i=0; i<numeroCampi; i++ )
			printf( "campo %d: %s\n", i, valori[i] );
		#endif
		
		strcpy( passwordUtente, valori[0] );
		return SQLITE_OK;
	}
	else
		return 0;
}


// Si connette al database SQLite e esegue la query per il recupero della password
int RetrievePassword( const char *name )
{
	int risultato;
	unsigned int lunghezzaNomeUtente;
	
	// Ricavo la lunghezza dell' nome utente immesso
	lunghezzaNomeUtente = strlen( name );
	
	// Se la lunghezza supera la lunghezza massima scelta, errore n°2
	if( lunghezzaNomeUtente >= MAX_USER_LENGTH )
	{
		fprintf( stderr, "[ERROR] Nome utente troppo lungo\n" );
		return 0;
	}
	
	// Copio (per comodità) il nome utente nel buffer apposito
	strncpy( nomeUtente, name, lunghezzaNomeUtente );
	
	#ifdef DB_DEBUG_MODE
	printf( "[DEBUG] Utente Cercato: %s\n", nomeUtente );
	#endif
	
	// Tento di "connettermi" al database Sqlite
	risultato = sqlite3_open( nomeDatabase, &connessioneDatabase );
	if( risultato != 0 )
	{
		fprintf( stderr, "[ERROR] Database utenti inesistente\n" );
		return 0;
	}
	
	// Composizione della prima query
	sprintf( queryBuffer, query_selezionaPassword, nomeUtente );
	
	#ifdef DB_DEBUG_MODE
	printf( "[DEBUG] Query: %s\n", queryBuffer );
	#endif
	
	// Recupero la password (se l'utente esiste)
	risultato = sqlite3_exec( connessioneDatabase, queryBuffer, GetPassword, 0, &outputErrori );
	if( risultato != SQLITE_OK )
	{
		fprintf( stderr, "[ERROR] Errore nel prelievo della password dell'utente %s\n", nomeUtente );
		return 0;
	}
	
	sqlite3_free( outputErrori );
	
	// Chiudo la connessione al database Sqlite
	sqlite3_close( connessioneDatabase );
	
	#ifdef DB_DEBUG_MODE
	printf( "[DEBUG] Password: %s\n", passwordUtente );
	#endif
	
	if( strlen( passwordUtente )<1 )
		return 0;
	return 1;
}

// Stabilisce una connessione sicura via SSL
int SSL_Connect( void )
{
	// Creazione del SSL Context
	ctx = SSL_CTX_new( SSLv23_client_method() );
	if( ctx == NULL )
	{
		fprintf( stderr, "[ERRORE] Impossibile creare l\'SSL context\n" );
		ERR_print_errors_fp( stderr );
		return 0;
	}
	
	// Creazione struttura dati per la connessione
	bio = BIO_new_ssl_connect( ctx );
	if( !bio )
	{
		ERR_print_errors_fp( stderr );
		fprintf( stderr, "[ERRORE] Impossibile creare BIO\n" );
		return 0;
	}
	
	// Settaggio impostazioni per la struttura di connessione
	BIO_get_ssl( bio, &ssl );
	SSL_set_mode( ssl, SSL_MODE_AUTO_RETRY );
	BIO_set_conn_hostname( bio, univaqLoginHost );
	
	// Connessione!
	if( BIO_do_connect( bio ) <=0 )
	{
		fprintf( stderr, "[ERRORE] Impossibile creare BIO\n" );
		ERR_print_errors_fp( stderr );
		ClearStructs( 3 );
		return 0;
	}
	
	// SSL Handshake
	if( BIO_do_handshake( bio ) <= 0 )
	{
		fprintf( stderr, "[ERRORE] Handshake fallito\n" );
		ERR_print_errors_fp( stderr );
		ClearStructs( 3 );
		return 0;
	}
	
	#ifdef NET_DEBUG_MODE
	X509 *cert; // Certificato
	char *line; // Dati (presi singolarmente) del certificato
	
	// Ricava il certificato dell'Host
	cert = SSL_get_peer_certificate( ssl );
	
	// Se valido...
	if ( cert != NULL )
	{
		line = X509_NAME_oneline( X509_get_subject_name(cert), 0, 0 );
		printf( "[DEBUG] Richiesto  : %s\n", line );
		
		free( line );
		
		line = X509_NAME_oneline( X509_get_issuer_name(cert), 0, 0 );
		printf( "[DEBUG] Richiedente: %s\n", line );
		
		free( line );
		X509_free( cert );
	}
	else
		printf( "Nessun Certificato.\n" );
	
	puts( "\n[DEBUG] Connessione avvenuta...\n" );
	#endif
	
	return 1; // Successo
}

// Invia dati
int SendData( char *dati )
{
	int len;
	
	// Invio dati
	len = BIO_puts( bio, dati );
	if( len<0 )
	{
		// Errore...è possibile riprovare?
		if( ! BIO_should_retry( bio ) )
		{
			// NO
			fprintf( stderr, "[ERRORE] Scrittura fallita\n" );
			ERR_print_errors_fp( stderr );
			ClearStructs( 3 );
			return -1;
		}
		
		// Inserire qua il codice per ritentare..
		fprintf( stderr, "[WARNING] Tentativo scrittura fallito\n" );
	}
	else
	{
		if( len==0 )
		{
			// Connessione chiusa
			fprintf( stderr, "\x1B[0;91m *** Connessione CHIUSA ***\x1B[0m" );
			return -1;
		}
	}
	return len;
}

// Legge dati
int ReadData( char *buffer, const unsigned long buffer_size )
{
	int len;
	
	// Se BIO non valido, ritorna -1
	if( bio == NULL )
		return -1;
	
	// Pulizia del buffer
	memset( buffer, 0, buffer_size );
	
	// Inizio lettura
	len = BIO_read( bio, buffer, buffer_size );
	if( len<0 )
	{
		// Errore...è possibile riprovare?
		if( ! BIO_should_retry( bio ) )
		{
			fprintf( stderr, "[ERRORE] Lettura fallita\n" );
			ERR_print_errors_fp( stderr );
			ClearStructs( 3 );
			return -1;
		}
		
		// Scrivere codice per riprovare
		fprintf( stderr, "[WARNING] Tentativo lettura fallito\n" );
	}
	else
	{
		if( len==0 )
		{
			// Connessione chiusa!
			fprintf( stderr, "\x1B[0;91m *** Connessione CHIUSA ***\x1B[0m" );
			return -1;
		}
	}
	
	return len;
}

// Libera la memoria delle strutture dati usate per la connessione e per l'SSL context
int ClearStructs( int quali_pulire )
{
	/*
	 * quali_pulire = 1 -> BIO
	 * quali_pulire = 2 -> CTX
	 * quali_pulire = 3 -> BIO+CTX
	*/
	if( bio == NULL && quali_pulire%2==1 )
		return 0;
	
	if( ctx == NULL && quali_pulire>1 )
		return 0;
	
	switch( quali_pulire )
	{
		case 1:
			BIO_free_all( bio );
			bio = NULL;
			break;
		case 2:
			SSL_CTX_free( ctx );
			break;
		case 3:
			BIO_free_all( bio );
			SSL_CTX_free( ctx );
	}
	
	return 1;
}

// Compone la richiesta POST
int PreparePostRequest( char *username, char *password )
{
	int postDataLength;
	char buffer[MAX_POST_DATA] = {0};
	
	// Creazione dei dati da spedire in POST 
	postDataLength = sprintf( buffer, univaqPostDataTemplate, username, password );
	
	if( postDataLength<=0 )
		return 0;
	
	// Creazione della richiesta POST
	sprintf( elaboredPostData, Request_2, postDataLength, buffer );
	return 1;
}