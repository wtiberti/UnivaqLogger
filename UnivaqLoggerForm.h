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

#ifndef UNIVAQLOGGER_FORMCLASS
	#define UNIVAQLOGGER_FORMCLASS

	#include <openssl/bio.h>
	#include <openssl/ssl.h>
	#include <openssl/err.h>
	
	#include <QtGui>
	#include "ui_interface.h"
	#include "defs.h"
	
	class UnivaqLoggerForm : public QWidget
	{
		Q_OBJECT
	public:
		UnivaqLoggerForm( QWidget *parent = NULL );
		~UnivaqLoggerForm();
	private:
		Ui::Form ui;
		
		int SSL_Connect( void );
		int ClearStructs( int quali_pulire );
		int PreparePostRequest( char *username, char *password );
		int SendData( char *dati );
		int ReadData( char *buffer, const unsigned long buffer_size );
		
		void LaunchBrowser( void );
		
		// Strutture per la connessione via OpenSSL
		BIO *bio; // Struttura BIO (OpenSSL)
		SSL *ssl; // Struttura SSL (OpenSSL)
		SSL_CTX *ctx; // OpenSSL Context
		
		char elaboredPostData[ MAX_POST_DATA ]; // Richiesta POST elaborata ( a partire dal template )
		char pageBuffer[ PAGE_BUFFER_LENGTH ] = { 0 }; // Buffer per la risposta del server
		
		// Buffer per nome utente e password
		char nomeUtente[ MAX_USER_LENGTH ] = { 0 };
		char passwordUtente[ MAX_PASSWORD_LENGTH ] = { 0 };
		
		char browserPath[256] = {0};
		
	public slots:
		void on_loginButton_clicked();
		void on_logoutButton_clicked();
	};

#endif