/*******************************************************************
WebSocket Protocol Implementation
Author: Marcin Kelar ( marcin.kelar@gmail.com )

xdigit and xstr2str functions from http://stackoverflow.com/questions/1557400/hex-to-char-array-in-c/1557493#1557493 by sambowry
*******************************************************************/
#include "include/string.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int xdigit( char digit ){
	int val;

	if( '0' <= digit && digit <= '9' ) {
		val = digit -'0';
	} else if( 'a' <= digit && digit <= 'f' ) {
		val = digit -'a'+10;
	} else if( 'A' <= digit && digit <= 'F' ) {
		val = digit -'A'+10;
	} else {
		val = -1;
	}

	return val;
}

int xstr2str( char *buf, unsigned bufsize, const char *in ){
	unsigned inlen;
	unsigned i, j;

	if( !in ) {
		return -1;
	}

	inlen = strlen( in );
	if( inlen % 2 != 0 ) {
		return -2;
	}

	for( i = 0; i < inlen; i++ ) {
		if( xdigit( in[i] ) < 0 ) {
			return -3;
		}
	}

	if( !buf || bufsize < inlen / 2 + 1 ) {
		return -4;
	}

	for( i = 0, j = 0; i < inlen; i += 2, j++ ) {
		buf[ j ] = xdigit( in[ i ] ) * 16 + xdigit( in[ i+1 ]);
	}

	buf[ inlen/2 ] = '\0';

	return inlen / 2+1;
}
