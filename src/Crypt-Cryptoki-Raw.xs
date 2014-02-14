#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <dlfcn.h>

#include "cryptoki/cryptoki.h"

#include "../../../src/const-c.inc"

typedef CK_FUNCTION_LIST*	Crypt__Cryptoki__Raw__FunctionList;

CK_FUNCTION_LIST* load( const char *param ) {
    CK_FUNCTION_LIST*	fl;
    CK_RV           	rc;
    CK_RV           	(*C_GetFunctionList)();
    void*           	d;

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



XS(boot_Crypt__Cryptoki__Raw__FunctionList); 

MODULE = Crypt::Cryptoki::Raw		PACKAGE = Crypt::Cryptoki::Raw		

INCLUDE: ../../../src/const-xs.inc

PROTOTYPES: ENABLE

BOOT:
	/*PUSHMARK(SP); if (items >= 2) { XPUSHs(ST(0)); XPUSHs(ST(1)); } PUTBACK; */
	boot_Crypt__Cryptoki__Raw__FunctionList(aTHX_ cv);
	/*SPAGAIN; POPs; */


Crypt::Cryptoki::Raw::FunctionList
load(param)
	const char *		param


