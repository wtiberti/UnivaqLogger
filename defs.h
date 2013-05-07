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

#ifndef UNIVAQLOGGER_DEF
	#define UNIVAQLOGGER_DEF
	
	// Debug modes
	//#define LOCAL_MODE
	#define NET_DEBUG_MODE
	
	
	// Browser utilizzato
	#define MY_BROWSER_CMD "which firefox"
	
	// definizione costanti
	#define PAGE_BUFFER_LENGTH 4096
	#define MAX_POST_DATA 1024
	#define MAX_USER_LENGTH 64
	#define MAX_PASSWORD_LENGTH 64

	// Dati per la richiesta
	static char univaqLoginHost[] = 
		#ifndef LOCAL_MODE
			"autenticazione.univaq.it:443";
		#else
			"localhost:443";
		#endif

	static char univaqPostDataTemplate[] = 
		"buttonClicked=4"
		"&redirect_url=autenticazione.univaq.it%%2F"
		"&err_flag=0"
		"&info_flag=0"
		"&info_msg=0"
		"&username=%s"
		"&password=%s";


	// Richiesta di prova
	static char Request_0[] =
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
	static char Request_1[] =
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
	static char Request_2[] =
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
#endif