/*******************************************************************

WebSocket Protocol Implementation

Author: Marcin Kelar ( marcin.kelar@gmail.com )
*******************************************************************/
#ifndef CWEBSOCKETS
#define CWEBSOCKETS

#include "base64.h"
#include "sha1.h"

#define WEBSOCKET_MAGIC_STRING				"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WEBSOCKET_KEY_HEADER				"Sec-WebSocket-Key: "
#define WEBSOCKET_CONNECTION_HEADER			"Connection: Upgrade"
#define WEBSOCKET_HANDSHAKE_RESPONSE		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n%s\r\nServer: Voyager 7\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n"

void	REQUEST_get_header_value( const char *data, const char *requested_value_name, char *dst, const unsigned int dst_len );

void	WEBSOCKET_generate_handshake( const char *data, char *dst, const unsigned int dst_len );
int		WEBSOCKET_set_content( const char *data, int data_length, unsigned char *dst, const unsigned int dst_len );
int		WEBSOCKET_get_content( const char *data, int data_length, unsigned char *dst, const unsigned int dst_len );
short	WEBSOCKET_valid_connection( const char *data );
int		WEBSOCKET_client_version( const char *data );

#endif
