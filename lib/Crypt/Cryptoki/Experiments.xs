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
	if ( SvROK(pStr) ) {
		if ( SvTYPE(SvRV(pStr)) >= SVt_PVAV ) {
			croak("must be a scalar reference");
		}
		SvREFCNT_dec(SvRV(pStr));
	}
	SV* _pStr = newSVpv("test",4);
	*pStr = *newRV_noinc(_pStr);
OUTPUT:
	pStr


int
is_array_ref(pArray)
	AV* pArray
CODE:
	printf("test_array_ref: 1\n");
	RETVAL = 1;
OUTPUT:
	RETVAL
	
	
void
array_ref(pArray)
	SV* pArray
CODE:
	if ( SvOK(pArray) ) {
		if (SvROK(pArray) && SvTYPE(SvRV(pArray)) == SVt_PVAV){
		    // pArray = SvRV(pArray);
		}
		else{
		    Perl_croak(aTHX_ "%s: %s is not an ARRAY reference",
				"Crypt::Cryptoki::Experiments::array_ref",
				"pArray");
		}
	}
	
=pod

	if ( SvROK((AV*)pArray) ) {
		SvGETMAGIC(pArray);
		printf("!!!  is ref\n");
		if ( SvTYPE(SvRV(pArray)) != SVt_PVAV ) {
			croak("must be a array reference");
		}
		SvREFCNT_dec(SvRV(pArray));
	}
	else if ( SvREADONLY(pArray) ) {
		printf("soso: RO\n");
	}
	else {
		printf("type: %d\n", SvTYPE(pArray));
		printf("pvav: %d\n", SVt_PVAV);
		printf("pvcv: %d\n", SVt_PVCV);
		printf("pvgv: %d\n", SVt_PVGV);
		printf("pvlv: %d\n", SVt_PVLV);
		printf("pvmg: %d\n", SVt_PVMG);
		printf("null: %d\n", SVt_NULL);
    printf("iv: %d\n", SVt_IV);
    printf("nv: %d\n", SVt_NV);
    printf("rv: %d\n", SVt_RV);
    printf("pv: %d\n", SVt_PV);
	}
	
=cut	
	
	// AV* _pArray = newAV();
	AV* _pArray = (AV*)pArray;
	av_clear(_pArray);
	av_push(_pArray, newSViv(1));
	av_push(_pArray, newSViv(2));
	av_push(_pArray, newSViv(3));
	av_push(_pArray, newSViv(4));
	// *pArray = *newRV_noinc((SV*)_pArray);
OUTPUT:
	pArray


void
hash_ref(pHash)
	SV* pHash
CODE:
	if ( SvROK(pHash) ) {
		if ( SvTYPE(SvRV(pHash)) != SVt_PVHV ) {
			croak("must be a hash reference");
		}
		SvREFCNT_dec(SvRV(pHash));
	}
	HV* _pHash = newHV();
	hv_store(_pHash, "one", 3, newSViv(1), 0);
	*pHash = *newRV_noinc((SV*)_pHash);
OUTPUT:
	pHash
