#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"


MODULE = Crypt::Cryptoki::Experiments							PACKAGE = Crypt::Cryptoki::Experiments		

PROTOTYPES: ENABLE

void
string_ref(pStr)
	SV* pStr
CODE:
	if ( !SvROK(pStr) || SvTYPE(SvRV(pStr)) >= SVt_PVAV ) {
		croak("is not a SCALAR reference");
	}
	SV* _pStr = SvRV(pStr);
	sv_setpv(_pStr, "test");
OUTPUT:
	pStr

	
void
array_ref(pArray)
	AV* pArray
CODE:
	av_clear(pArray);
	av_push(pArray, newSViv(1));
	av_push(pArray, newSViv(2));
	av_push(pArray, newSViv(3));
	av_push(pArray, newSViv(4));
OUTPUT:
	pArray


void
hash_ref(pHash)
	HV*	pHash
CODE:
	hv_clear(pHash);
	hv_store(pHash, "one", 3, newSViv(1), 0);
OUTPUT:
	pHash
