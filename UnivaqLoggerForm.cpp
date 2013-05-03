/*
 * This file is part of UnivaqLogger software.
 *
 * UnivaqLogger is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * UnivaqLogger is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with UnivaqLogger.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2013 Walter Tiberti
 */

#include <cstdio>
#include <cstring>

#include "UnivaqLoggerForm.h"
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


UnivaqLoggerForm::UnivaqLoggerForm( QWidget *parent ) : QWidget( parent )
{
	ui.setupUi( this );
	
	bio = NULL;
	ssl = NULL;
	ctx = NULL;
}

UnivaqLoggerForm::~UnivaqLoggerForm()
{
	ClearStructs( 3 );
}

int UnivaqLoggerForm::SSL_Connect( void )
{
	// Creazione del SSL Context
	ctx = SSL_CTX_new( SSLv23_client_method() );
	if( ctx == NULL )
	{
		fprintf( stderr, "[ERRORE] Impossibile creare l\'SSL context\n" );
		ERR_print_errors_fp( stderr );
		return 0;
	}
	
	#ifdef NET_DEBUG_MODE
	puts( "[DEBUG] Context SSL creato" );
	#endif
	
	// Creazione struttura dati per la connessione
	bio = BIO_new_ssl_connect( ctx );
	if( !bio )
	{
		ERR_print_errors_fp( stderr );
		fprintf( stderr, "[ERRORE] Impossibile creare BIO\n" );
		return 0;
	}
	
	#ifdef NET_DEBUG_MODE
	puts( "[DEBUG] Connessione SSL inizializzata" );
	#endif
	
	// Settaggio impostazioni per la struttura di connessione
	BIO_get_ssl( bio, &ssl );
	SSL_set_mode( ssl, SSL_MODE_AUTO_RETRY );
	BIO_set_conn_hostname( bio, univaqLoginHost );
	
	#ifdef NET_DEBUG_MODE
	puts( "[DEBUG] Connessione SSL regolata" );
	#endif
	
	// Connessione!
	if( BIO_do_connect( bio ) <=0 )
	{
		fprintf( stderr, "[ERRORE] Impossibile creare BIO\n" );
		ERR_print_errors_fp( stderr );
		ClearStructs( 3 );
		return 0;
	}
	
	#ifdef NET_DEBUG_MODE
	puts( "[DEBUG] Connessione SSL effettuata" );
	#endif
	
	// SSL Handshake
	if( BIO_do_handshake( bio ) <= 0 )
	{
		fprintf( stderr, "[ERRORE] Handshake fallito\n" );
		ERR_print_errors_fp( stderr );
		ClearStructs( 3 );
		return 0;
	}
	
	#ifdef NET_DEBUG_MODE
	puts( "[DEBUG] Handshake avviato" );
	#endif
	
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

int UnivaqLoggerForm::SendData( char *dati )
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

int UnivaqLoggerForm::ReadData( char *buffer, const unsigned long buffer_size )
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

int UnivaqLoggerForm::ClearStructs( int quali_pulire )
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
			ctx = NULL;
			break;
		case 3:
			BIO_free_all( bio );
			SSL_CTX_free( ctx );
			bio = NULL;
			ctx = NULL;
	}
	
	return 1;
}

int UnivaqLoggerForm::PreparePostRequest( char *username, char *password )
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

void UnivaqLoggerForm::on_loginButton_clicked()
{
	if( ui.nameEdit->text().size() == 0 || ui.passwordEdit->text().length() == 0 )
	{
		fprintf( stderr, "[ERRORE] Campi non riempiti.\n" );
		return;
	}
	
	strncpy( nomeUtente, ui.nameEdit->text().toStdString().c_str(), ui.nameEdit->text().size() );
	strncpy( passwordUtente, ui.passwordEdit->text().toStdString().c_str(), ui.passwordEdit->text().size() );
	
	if( ! PreparePostRequest( nomeUtente, passwordUtente ) )
	{
		fprintf( stderr, "[ERRORE] Creazione dati POST non riuscita.\n" );
		return;
	}
	
	// Inizializzazione OpenSSL
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	SSL_library_init();
	
	// Connessione SSL
	if( SSL_Connect() )
	{
		// test numero #1
		/*
		#ifdef NET_DEBUG_M*ODE
		printf( "\x1B[0;94m%s\x1B[0;92m", Request_1 );
		SendData( Request_1 );
		while( ReadData( pageBuffer, PAGE_BUFFER_LENGTH-2 ) > 0 )
		{
			#ifdef NET_DEBUG_MODE
			pageBuffer[PAGE_BUFFER_LENGTH-1] = 0;
			puts( pageBuffer );
			fflush( stdout );
			#endif
		}
		#ifdef NET_DEBUG_MODE
		puts( "\x1B[0m" );
		#endif
		*/
		
		#ifdef NET_DEBUG_MODE
		printf( "\x1B[0;94m%s\x1B[0;92m\n", elaboredPostData );
		#endif
		SendData( elaboredPostData );
		while( ReadData( pageBuffer, PAGE_BUFFER_LENGTH-2 ) > 0 )
		{
			#ifdef NET_DEBUG_MODE
			pageBuffer[PAGE_BUFFER_LENGTH-1] = 0;
			puts( pageBuffer );
			fflush( stdout );
			#endif
		}
		#ifdef NET_DEBUG_MODE
		puts( "\x1B[0m" );
		#endif
		
	}
	else
		fprintf( stderr, "[ERRORE] Connessione non riuscita.\n" );
}