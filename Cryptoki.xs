#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <dlfcn.h>

#include "cryptoki/cryptoki.h"

#include "const-c.inc"

typedef CK_FUNCTION_LIST*	Cryptoki__FunctionList;


CK_FUNCTION_LIST* load( const char *param )
{
    CK_FUNCTION_LIST	*fl;
    CK_RV           	rc;
    CK_RV           	(*C_GetFunctionList)();
    void           		*d;

    d = dlopen(param, RTLD_LAZY | RTLD_LOCAL);
    if ( d == NULL ) {
        d = dlopen(param, RTLD_LAZY);
        if (d == NULL ) {
            return NULL;
        }
    }

    C_GetFunctionList = (CK_RV (*)())dlsym(d,"C_GetFunctionList");
    if (C_GetFunctionList == NULL ) {
        printf("Symbol lookup failed\n");
        return NULL;
    }

    rc = C_GetFunctionList(&fl);

    if (rc != CKR_OK) {
        printf("Call to C_GetFunctionList failed\n");
        fl = NULL;
    }

    return fl;
}





XS(boot_Cryptoki__FunctionList); 

MODULE = Cryptoki		PACKAGE = Cryptoki		

INCLUDE: const-xs.inc

PROTOTYPES: ENABLE

BOOT:
	//PUSHMARK(SP); if (items >= 2) { XPUSHs(ST(0)); XPUSHs(ST(1)); } PUTBACK;
	//boot_Cryptoki__Info(aTHX_ cv);
	//SPAGAIN; POPs;

	//PUSHMARK(SP); if (items >= 2) { XPUSHs(ST(0)); XPUSHs(ST(1)); } PUTBACK;
	boot_Cryptoki__FunctionList(aTHX_ cv);
	//SPAGAIN; POPs;


Cryptoki::FunctionList
load(param)
	const char *		param


