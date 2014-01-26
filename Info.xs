#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "cryptoki/cryptoki.h"

#include "const-c.inc"

typedef CK_INFO*		Cryptoki__Info;

MODULE = Cryptoki::Info		PACKAGE = Cryptoki::Info		

INCLUDE: const-xs.inc

PROTOTYPES: ENABLE


const char*
manufacturerID(info)
	Cryptoki::Info	info
CODE:
	RETVAL = (char*)info->manufacturerID;
OUTPUT:
	RETVAL
	
