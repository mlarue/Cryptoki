#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"
#include <dlfcn.h>
#include "cryptoki/cryptoki.h"

typedef struct raw {
	void*             handle;
	CK_FUNCTION_LIST* function_list;
} raw_t;

typedef raw_t* Crypt__Cryptoki__Raw;

CK_RV notify_callback(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event,CK_VOID_PTR pApplication) {
	warn("notify\n");
	return CKR_OK;
}


MODULE = Crypt::Cryptoki::Raw                    PACKAGE = Crypt::Cryptoki::Raw

PROTOTYPES: ENABLE

TYPEMAP: <<HERE

TYPEMAP
CK_ATTRIBUTE_PTR  T_TEMPLATE

INPUT
T_TEMPLATE
	STMT_START {
		SV* const xsub_tmp_sv = $arg;
		if (SvROK(xsub_tmp_sv) && SvTYPE(SvRV(xsub_tmp_sv)) == SVt_PVAV){
			AV* aTemplate = (AV*)SvRV(xsub_tmp_sv);
			$var\_count = av_top_index(aTemplate)+1;
			Newxz($var, $var\_count, CK_ATTRIBUTE);
			int i = 0;
			for(i=0;i<$var\_count;++i){
				SV** elem = av_fetch(aTemplate, i, 0);
				if ( elem == NULL || SvTYPE(SvRV(*elem)) != SVt_PVAV ) {
					croak(\"Error: wrong argument\");
				}
				AV* attr = (AV*)SvRV(*elem);
				size_t attr_count = av_top_index(attr) + 1;

				if ( attr_count > 0 ) {
					$var\[i\].type = SvUV(*av_fetch(attr, 0, 0));
				}

				if ( attr_count == 1 ) {
					$var\[i\].pValue = NULL;
					$var\[i\].ulValueLen = 0;
				}
				else if ( attr_count == 2 ) {
					// TODO: special case: pValue is array of attributes
					SV* _value = *av_fetch(attr, 1, 0);
					CK_ULONG _len = sv_len(_value);
					$var\[i\].pValue = (void*)SvPV(_value, _len);
					$var\[i\].ulValueLen = _len;
				}
				else {
					croak(\"Illegal array length in argument\");
				}
			}
		}
		else {
			Perl_croak(aTHX_ \"%s: %s is not an ARRAY reference\",
				${$ALIAS?\q[GvNAME(CvGV(cv))]:\qq[\"$pname\"]},
				\"$var\");
		}
	} STMT_END

OUTPUT
T_TEMPLATE
	{
		if ( RETVAL == CKR_OK ) {
			SV* const xsub_tmp_sv = $arg;
			AV* aTemplate = (AV*)SvRV(xsub_tmp_sv);
			int i;
			for(i=0;i<$var\_count;++i){
				AV* attr = (AV*)SvRV(*av_fetch(aTemplate, i, 0));
				av_store(attr, 1, newSVpv($var\[i\].pValue, $var\[i\].ulValueLen));
			}
		}
		Safefree($var);
	}

HERE





Crypt::Cryptoki::Raw
new( const char *class, const char *library_path )
CODE:
	CK_RV	(*C_GetFunctionList)();

	RETVAL = (raw_t*)calloc(1,sizeof(raw_t));
	if (! RETVAL) {
		croak("No memory for %s", class);
	}

	RETVAL->handle = dlopen(library_path, RTLD_LAZY | RTLD_LOCAL);
	if (! RETVAL->handle ) {
		croak("Can not open library");
	}

	C_GetFunctionList = (CK_RV (*)())dlsym(RETVAL->handle,"C_GetFunctionList");
	if (C_GetFunctionList == NULL ) {
		croak("Symbol lookup failed");
	}

	CK_RV rc = C_GetFunctionList(&RETVAL->function_list);
	if (rc != CKR_OK) {
		croak("Call to C_GetFunctionList failed");
	}
OUTPUT: 
	RETVAL



void
DESTROY(self)
	Crypt::Cryptoki::Raw  self
CODE:
	if (dlclose(self->handle)) {
		warn("dlclose problem");
	};
	free(self);

################################################################################
#
# General purpose functions
#

CK_RV
C_Initialize(self)
	Crypt::Cryptoki::Raw  self
CODE:
	RETVAL = self->function_list->C_Initialize(NULL);
OUTPUT:
	RETVAL


CK_RV
C_Finalize(self)
	Crypt::Cryptoki::Raw  self
CODE:
	RETVAL = self->function_list->C_Finalize(NULL);
OUTPUT:
	RETVAL


CK_RV
C_GetInfo(self,info)
	Crypt::Cryptoki::Raw  self
	HV*                   info
CODE:
	CK_INFO _info;
	RETVAL = self->function_list->C_GetInfo(&_info);
	if (RETVAL == CKR_OK) {
		hv_store(info, "cryptokiVersion", 15, 
			newSVpvf("%d.%d",_info.cryptokiVersion.major,_info.cryptokiVersion.minor), 0);
		hv_store(info, "manufacturerID", 14, newSVpv((char*)_info.manufacturerID,32), 0);
		hv_store(info, "flags", 5, newSViv(_info.flags), 0);
		hv_store(info, "libraryDescription", 18, newSVpv((char*)_info.libraryDescription,32), 0);
		hv_store(info, "libraryVersion", 14, 
			newSVpvf("%d.%d",_info.libraryVersion.major,_info.libraryVersion.minor),0);
	}
OUTPUT:
	RETVAL
	info


################################################################################
#
# Slot and token management functions
#

CK_RV
C_GetSlotList(self,tokenPresent,pSlotList)
	Crypt::Cryptoki::Raw  self
	CK_BBOOL              tokenPresent
	AV*                   pSlotList
CODE:
	CK_ULONG pulCount;

	RETVAL = self->function_list->C_GetSlotList(tokenPresent,NULL_PTR,&pulCount);

	if ( RETVAL == CKR_OK ) {
		CK_SLOT_ID_PTR _pSlotList;
		Newxz(_pSlotList, pulCount, CK_SLOT_ID);

		RETVAL = self->function_list->C_GetSlotList(tokenPresent,_pSlotList,&pulCount);

		if ( RETVAL == CKR_OK ) {
			unsigned int i = 0;
			for(i=0;i<pulCount;i++) {
				av_push((AV*)pSlotList,newSViv(_pSlotList[i]));
			}
		}

		Safefree(_pSlotList);
	}
OUTPUT:
	RETVAL
	pSlotList


CK_RV
C_GetSlotInfo(self,slotID,pInfo)
	Crypt::Cryptoki::Raw  self
	CK_SLOT_ID            slotID
	HV*                   pInfo
CODE:
	CK_SLOT_INFO _pInfo;
	RETVAL = self->function_list->C_GetSlotInfo(slotID,&_pInfo);
	if (RETVAL == CKR_OK) {
		hv_store(pInfo, "slotDescription", 15, newSVpv((char*)_pInfo.slotDescription,64), 0);
		hv_store(pInfo, "manufacturerID", 14, newSVpv((char*)_pInfo.manufacturerID,32), 0);
		hv_store(pInfo, "flags", 5, newSViv(_pInfo.flags), 0);
		hv_store(pInfo, "hardwareVersion", 15, 
			newSVpvf("%d.%d",_pInfo.hardwareVersion.major,_pInfo.hardwareVersion.minor), 0);
		hv_store(pInfo, "firmwareVersion", 15, 
			newSVpvf("%d.%d",_pInfo.firmwareVersion.major,_pInfo.firmwareVersion.minor), 0);
	}	
OUTPUT:
	RETVAL
	pInfo


CK_RV
C_GetTokenInfo(self,slotID,pInfo)
	Crypt::Cryptoki::Raw  self
	CK_SLOT_ID            slotID
	HV*                   pInfo
CODE:
	CK_TOKEN_INFO _pInfo;
	RETVAL = self->function_list->C_GetTokenInfo(slotID,&_pInfo);
	if (RETVAL == CKR_OK) {
		hv_store(pInfo, "label", 5, newSVpv((char*)_pInfo.label,32), 0);
		hv_store(pInfo, "manufacturerID", 14, newSVpv((char*)_pInfo.manufacturerID,32), 0);
		hv_store(pInfo, "model", 5, newSVpv((char*)_pInfo.model,16), 0);
		hv_store(pInfo, "serialNumber", 12, newSVpv((char*)_pInfo.serialNumber,16), 0);
		hv_store(pInfo, "flags", 5, newSViv(_pInfo.flags), 0);
		hv_store(pInfo, "ulMaxSessionCount", 17, newSVuv(_pInfo.ulMaxSessionCount), 0);
		hv_store(pInfo, "ulSessionCount", 14, newSVuv(_pInfo.ulSessionCount), 0);
		hv_store(pInfo, "ulMaxRwSessionCount", 19, newSVuv(_pInfo.ulMaxRwSessionCount), 0);
		hv_store(pInfo, "ulRwSessionCount", 16, newSVuv(_pInfo.ulRwSessionCount), 0);
		hv_store(pInfo, "ulMaxPinLen", 11, newSVuv(_pInfo.ulMaxPinLen), 0);
		hv_store(pInfo, "ulMinPinLen", 11, newSVuv(_pInfo.ulMinPinLen), 0);
		hv_store(pInfo, "ulTotalPublicMemory", 19, newSVuv(_pInfo.ulTotalPublicMemory), 0);
		hv_store(pInfo, "ulFreePublicMemory", 18, newSVuv(_pInfo.ulFreePublicMemory), 0);
		hv_store(pInfo, "ulTotalPrivateMemory", 20, newSVuv(_pInfo.ulTotalPrivateMemory), 0);
		hv_store(pInfo, "ulFreePrivateMemory", 19, newSVuv(_pInfo.ulFreePrivateMemory), 0);
		hv_store(pInfo, "hardwareVersion", 15, 
			newSVpvf("%d.%d",_pInfo.hardwareVersion.major,_pInfo.hardwareVersion.minor), 0);
		hv_store(pInfo, "firmwareVersion", 15, 
			newSVpvf("%d.%d",_pInfo.firmwareVersion.major,_pInfo.firmwareVersion.minor), 0);
		hv_store(pInfo, "utcTime", 7, newSVpv((char*)_pInfo.utcTime,16), 0);
	}	
OUTPUT:
	RETVAL
	pInfo


CK_RV
C_WaitForSlotEvent(self,flags,pSlot)
	Crypt::Cryptoki::Raw  self
	CK_FLAGS              flags
	SV*                   pSlot
CODE:
	CK_SLOT_ID _slotID;
	RETVAL = self->function_list->C_WaitForSlotEvent(flags,&_slotID,NULL_PTR);
	if ( RETVAL==CKR_OK ) {
		*pSlot = *newSViv(_slotID);
	}
OUTPUT:
	RETVAL
	pSlot


CK_RV
C_GetMechanismList(self,slotID,pMechanismList)
	Crypt::Cryptoki::Raw  self
	CK_SLOT_ID            slotID
	AV*                   pMechanismList
CODE:
	CK_ULONG pulCount;
	RETVAL = self->function_list->C_GetMechanismList(slotID,NULL_PTR,&pulCount);
	if ( RETVAL == CKR_OK ) {
		CK_MECHANISM_TYPE_PTR _pMechanismList;
		Newxz(_pMechanismList, pulCount, CK_MECHANISM_TYPE);
		RETVAL = self->function_list->C_GetMechanismList(slotID,_pMechanismList,&pulCount);
		if ( RETVAL == CKR_OK ) {
			unsigned int i = 0;
			for(i=0;i<pulCount;i++) {
				av_push((AV*)pMechanismList,newSViv(_pMechanismList[i]));
			}
		}
		Safefree(_pMechanismList);
	}
OUTPUT:
	RETVAL
	pMechanismList


CK_RV
C_GetMechanismInfo(self,slotID,type,pInfo)
	Crypt::Cryptoki::Raw  self
	CK_SLOT_ID            slotID
	CK_MECHANISM_TYPE     type
	HV*                   pInfo
CODE:
	CK_MECHANISM_INFO _pInfo;
	RETVAL = self->function_list->C_GetMechanismInfo(slotID,type,&_pInfo);
	if (RETVAL == CKR_OK) {
		hv_store(pInfo, "ulMinKeySize", 12, newSVuv(_pInfo.ulMinKeySize), 0);
		hv_store(pInfo, "ulMaxKeySize", 12, newSVuv(_pInfo.ulMaxKeySize), 0);
		hv_store(pInfo, "flags", 5, newSViv(_pInfo.flags), 0);
	}
OUTPUT:
	RETVAL
	pInfo


CK_RV
C_InitToken(self,slotID,pPin,ulPinLen,pLabel)
	Crypt::Cryptoki::Raw  self
	CK_SLOT_ID            slotID
	char*                 pPin
	CK_ULONG              ulPinLen
	char*                 pLabel
CODE:
	RETVAL = self->function_list->C_InitToken(slotID,(CK_UTF8CHAR_PTR)pPin,ulPinLen,(CK_UTF8CHAR_PTR)pLabel);
OUTPUT:
	RETVAL


CK_RV
C_InitPIN(self,hSession,pPin,ulPinLen)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	char*                 pPin
	CK_ULONG              ulPinLen
CODE:
	RETVAL = self->function_list->C_InitPIN(hSession,(CK_UTF8CHAR_PTR)pPin,ulPinLen);
OUTPUT:
	RETVAL


CK_RV
C_SetPIN(self,hSession,pOldPin,ulOldLen,pNewPin,ulNewLen)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	char*                 pOldPin
	CK_ULONG              ulOldLen
	char*                 pNewPin
	CK_ULONG              ulNewLen
CODE:
	RETVAL = self->function_list->C_SetPIN(
		hSession,
		(CK_UTF8CHAR_PTR)pOldPin,ulOldLen,
		(CK_UTF8CHAR_PTR)pNewPin,ulNewLen
	);
OUTPUT:
	RETVAL

	
################################################################################
#
# Session management functions
#

CK_RV
C_OpenSession(self,slotID,flags,phSession)
	Crypt::Cryptoki::Raw  self
	CK_SLOT_ID            slotID
	CK_FLAGS              flags
//  CK_VOID_PTR         pApplication
//  CK_NOTIFY           Notify
	SV*                   phSession
CODE:
	// TODO: pass perl callback to wrapper and call it there
	CK_NOTIFY Notify = &notify_callback;
	CK_SESSION_HANDLE _hSession;
	RETVAL = self->function_list->C_OpenSession(slotID,flags,NULL_PTR,Notify,&_hSession);
	if ( RETVAL==CKR_OK ) {
		*phSession = *newSViv(_hSession);
	}
OUTPUT:
	RETVAL
	phSession


CK_RV
C_CloseSession(self,hSession)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
CODE:
	RETVAL = self->function_list->C_CloseSession(hSession);
OUTPUT:
	RETVAL


CK_RV
C_CloseAllSessions(self,slotID)
	Crypt::Cryptoki::Raw  self
	CK_SLOT_ID            slotID
CODE:
	RETVAL = self->function_list->C_CloseAllSessions(slotID);
OUTPUT:
	RETVAL


CK_RV
C_GetSessionInfo(self,hSession,pInfo)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	HV*                   pInfo
CODE:
	CK_SESSION_INFO _pInfo;
	RETVAL = self->function_list->C_GetSessionInfo(hSession,&_pInfo);
	if (RETVAL == CKR_OK) {
		hv_store(pInfo, "slotID", 6, newSVuv(_pInfo.slotID), 0);
		hv_store(pInfo, "state", 5, newSVuv(_pInfo.state), 0);
		hv_store(pInfo, "flags", 5, newSViv(_pInfo.flags), 0);
		hv_store(pInfo, "ulDeviceError", 13, newSVuv(_pInfo.ulDeviceError), 0);
	}
OUTPUT:
	RETVAL
	pInfo


CK_RV
C_Login(self,hSession,userType,pPin)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	CK_USER_TYPE          userType
	CK_UTF8CHAR_PTR       pPin
CODE:
	CK_ULONG ulPinLen = strlen((const char *)pPin);
	RETVAL = self->function_list->C_Login(hSession,userType,pPin,ulPinLen);
OUTPUT:
	RETVAL


CK_RV
C_Logout(self,hSession)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
CODE:
	RETVAL = self->function_list->C_Logout(hSession);
OUTPUT:
	RETVAL

# TODO: C_GetOperationState
# TODO: C_SetOperationState


################################################################################
#
# Object management functions
#

# TODO: Test C_CreateObject / SoftHSM hassle?

CK_RV
C_CreateObject(self,hSession,pTemplate,phObject)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	CK_ATTRIBUTE_PTR      pTemplate
	CK_OBJECT_HANDLE      phObject
PREINIT:
	CK_ULONG pTemplate_count;
CODE:
	RETVAL = self->function_list->C_CreateObject(
		hSession,
		pTemplate,
		pTemplate_count,
		&phObject
	);
	Safefree(pTemplate);
OUTPUT:
	RETVAL
	phObject


CK_RV
C_DestroyObject(self,hSession,hObject)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	CK_OBJECT_HANDLE      hObject
CODE:
	RETVAL = self->function_list->C_DestroyObject(hSession,hObject);
OUTPUT:
	RETVAL


CK_RV
C_GetAttributeValue(self,hSession,hObject,pTemplate)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	CK_OBJECT_HANDLE      hObject
	CK_ATTRIBUTE_PTR      pTemplate
PREINIT:
	CK_ULONG pTemplate_count;
CODE:
	RETVAL = self->function_list->C_GetAttributeValue(
		hSession,
		hObject,
		pTemplate,
		pTemplate_count
	);

	if ( RETVAL == CKR_OK ) {
		int i = 0;
		for(i=0;i<pTemplate_count;++i){
			if ( pTemplate[i].ulValueLen == -1 ) {
				croak("Error: attribute %d",i);
			}
			Newx(pTemplate[i].pValue,pTemplate[i].ulValueLen,CK_BYTE);
		}
		RETVAL = self->function_list->C_GetAttributeValue(
			hSession,
			hObject,
			pTemplate,
			pTemplate_count
		);
	}
OUTPUT:
	RETVAL
	pTemplate

# TODO: C_CopyObject
# TODO: C_GetObjectSize
# TODO: C_SetAttributeValue
# TODO: C_FindObjectsInit
# TODO: C_FindObjects
# TODO: C_FindObjectsFinal


################################################################################
#
# Encryption functions
#

CK_RV
C_EncryptInit(self,hSession,pMechanism,hKey)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	AV*                   pMechanism
	CK_OBJECT_HANDLE      hKey
CODE:
	CK_MECHANISM _pMechanism;
	_pMechanism.mechanism = SvUV(*av_fetch(pMechanism, 0, 0));
	_pMechanism.pParameter = NULL_PTR;
	_pMechanism.ulParameterLen = 0; 
	RETVAL = self->function_list->C_EncryptInit(hSession,&_pMechanism,hKey);
OUTPUT:
	RETVAL


CK_RV
C_Encrypt(self,hSession,pData,ulDataLen,pEncryptedData,ulEncryptedDataLen)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	char*                 pData
	CK_ULONG              ulDataLen
	SV*                   pEncryptedData
	CK_ULONG              ulEncryptedDataLen
CODE:
	RETVAL = self->function_list->C_Encrypt(hSession,(CK_BYTE_PTR)pData,ulDataLen,
		NULL_PTR,&ulEncryptedDataLen);
	if ( RETVAL==CKR_OK ) {
		CK_BYTE_PTR _pEncryptedData;
		Newx(_pEncryptedData,ulEncryptedDataLen,CK_BYTE);
		RETVAL = self->function_list->C_Encrypt(hSession,(CK_BYTE_PTR)pData,ulDataLen,
			_pEncryptedData,&ulEncryptedDataLen);

		if ( RETVAL==CKR_OK ) {
			*pEncryptedData = *newSVpv((char*)_pEncryptedData,ulEncryptedDataLen);
		}
	}
OUTPUT:
	RETVAL
	pEncryptedData
	ulEncryptedDataLen


CK_RV
C_EncryptUpdate(self,hSession,pPart,ulPartLen,pEncryptedPart,ulEncryptedPartLen)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	char*                 pPart
	CK_ULONG              ulPartLen
	SV*                   pEncryptedPart
	CK_ULONG              ulEncryptedPartLen
CODE:
	CK_BYTE_PTR _pEncryptedPart;
	Newx(_pEncryptedPart,ulEncryptedPartLen,CK_BYTE);

	RETVAL = self->function_list->C_EncryptUpdate(
		hSession,(CK_BYTE_PTR)pPart,ulPartLen,_pEncryptedPart,&ulEncryptedPartLen
	);
	
	if ( RETVAL==CKR_OK ) {
		*pEncryptedPart = *newSVpv((char*)_pEncryptedPart,ulEncryptedPartLen);
	}
OUTPUT:
	RETVAL
	pEncryptedPart
	ulEncryptedPartLen


CK_RV
C_EncryptFinal(self,hSession,pEncryptedPart,ulEncryptedPartLen)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	SV*                   pEncryptedPart
	CK_ULONG              ulEncryptedPartLen
CODE:
	CK_BYTE_PTR _pEncryptedPart;
	Newx(_pEncryptedPart,ulEncryptedPartLen,CK_BYTE);

	RETVAL = self->function_list->C_EncryptFinal(
		hSession,_pEncryptedPart,&ulEncryptedPartLen
	);
	
	if ( RETVAL==CKR_OK ) {
		*pEncryptedPart = *newSVpv((char*)_pEncryptedPart,ulEncryptedPartLen);
	}
OUTPUT:
	RETVAL
	pEncryptedPart
	ulEncryptedPartLen


################################################################################
#
# Decryption functions
#

CK_RV
C_DecryptInit(self,hSession,pMechanism,hKey)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	AV*                   pMechanism
	CK_OBJECT_HANDLE      hKey
CODE:
	CK_MECHANISM	 		_pMechanism;
	_pMechanism.mechanism = SvUV(*av_fetch(pMechanism, 0, 0));
	_pMechanism.pParameter = NULL_PTR;
	_pMechanism.ulParameterLen = 0; 
	RETVAL = self->function_list->C_DecryptInit(hSession,&_pMechanism,hKey);
OUTPUT:
	RETVAL


CK_RV
C_Decrypt(self,hSession,pEncryptedData,ulEncryptedDataLen,pData,ulDataLen)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	char*                 pEncryptedData
	CK_ULONG              ulEncryptedDataLen
	SV*                   pData
	CK_ULONG              ulDataLen
CODE:
	RETVAL = self->function_list->C_Decrypt(hSession,(CK_BYTE_PTR)pEncryptedData,ulEncryptedDataLen,
		NULL_PTR,&ulDataLen);
	if ( RETVAL==CKR_OK ) {
		CK_BYTE_PTR _pData;
		Newx(_pData,ulDataLen,CK_BYTE);
		RETVAL = self->function_list->C_Decrypt(hSession,(CK_BYTE_PTR)pEncryptedData,ulEncryptedDataLen,
			_pData,&ulDataLen);

		if ( RETVAL==CKR_OK ) {
			*pData = *newSVpv((char*)_pData, ulDataLen);
		}
	}
OUTPUT:
	RETVAL
	pData
	ulDataLen

# TODO: C_DecryptUpdate
# TODO: C_DecryptFinal 


################################################################################
#
# Message digesting functions
#

CK_RV
C_DigestInit(self,hSession,pMechanism)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	AV*                   pMechanism
CODE:
	CK_MECHANISM _pMechanism;
	_pMechanism.mechanism = SvUV(*av_fetch(pMechanism, 0, 0));
	_pMechanism.pParameter = NULL_PTR;
	_pMechanism.ulParameterLen = 0; 
	RETVAL = self->function_list->C_DigestInit(hSession,&_pMechanism);
OUTPUT:
	RETVAL


CK_RV
C_Digest(self,hSession,pData,ulDataLen,pDigest,ulDigestLen)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	char*                 pData
	CK_ULONG              ulDataLen
	SV*                   pDigest
	CK_ULONG              ulDigestLen
CODE:
	RETVAL = self->function_list->C_Digest(hSession,(CK_BYTE_PTR)pData,ulDataLen,
		NULL_PTR,&ulDigestLen);
	if ( RETVAL==CKR_OK ) {
		CK_BYTE_PTR _pDigest;
		Newx(_pDigest,ulDigestLen,CK_BYTE);
		RETVAL = self->function_list->C_Digest(hSession,(CK_BYTE_PTR)pData,ulDataLen,
			_pDigest,&ulDigestLen);

		if ( RETVAL==CKR_OK ) {
			*pDigest = *newSVpv((char*)_pDigest, ulDigestLen);
		}
	}
OUTPUT:
	RETVAL
	pDigest
	ulDigestLen


# TODO: C_DigestUpdate
# TODO: C_DigestKey
# TODO: C_DigestFinal

################################################################################
#
# Signing and MACing functions
#

CK_RV
C_SignInit(self,hSession,pMechanism,hKey)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	AV*                   pMechanism
	CK_OBJECT_HANDLE      hKey
CODE:
	CK_MECHANISM _pMechanism;
	_pMechanism.mechanism = SvUV(*av_fetch(pMechanism, 0, 0));
	_pMechanism.pParameter = NULL_PTR;
	_pMechanism.ulParameterLen = 0; 
	RETVAL = self->function_list->C_SignInit(hSession,&_pMechanism,hKey);
OUTPUT:
	RETVAL


CK_RV
C_Sign(self,hSession,pData,ulDataLen,pSignature,ulSignatureLen)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	char*                 pData
	CK_ULONG              ulDataLen
	SV*                   pSignature
	CK_ULONG              ulSignatureLen
CODE:
	RETVAL = self->function_list->C_Sign(hSession,(CK_BYTE_PTR)pData,ulDataLen,
		NULL_PTR,&ulSignatureLen);
	if ( RETVAL==CKR_OK ) {
		CK_BYTE_PTR _pSignature;
		Newx(_pSignature,ulSignatureLen,CK_BYTE);
		RETVAL = self->function_list->C_Sign(hSession,(CK_BYTE_PTR)pData,ulDataLen,
			_pSignature,&ulSignatureLen);

		if ( RETVAL==CKR_OK ) {
			*pSignature = *newSVpv((char*)_pSignature, ulSignatureLen);
		}
	}
OUTPUT:
	RETVAL
	pSignature
	ulSignatureLen

# TODO: C_SignUpdate
# TODO: C_SignFinal
# TODO: C_SignRecoverInit
# TODO: C_SignRecover

################################################################################
#
# Functions for verifying signatures and MACs
#

CK_RV
C_VerifyInit(self,hSession,pMechanism,hKey)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	AV*                   pMechanism
	CK_OBJECT_HANDLE      hKey
CODE:
	CK_MECHANISM _pMechanism;
	_pMechanism.mechanism = SvUV(*av_fetch(pMechanism, 0, 0));
	_pMechanism.pParameter = NULL_PTR;
	_pMechanism.ulParameterLen = 0; 
	RETVAL = self->function_list->C_VerifyInit(hSession,&_pMechanism,hKey);
OUTPUT:
	RETVAL


CK_RV
C_Verify(self,hSession,pData,ulDataLen,pSignature,ulSignatureLen)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	char*                 pData
	CK_ULONG              ulDataLen
	char*                 pSignature
	CK_ULONG              ulSignatureLen
CODE:
	RETVAL = self->function_list->C_Verify(hSession,(CK_BYTE_PTR)pData,ulDataLen,
		(CK_BYTE_PTR)pSignature,ulSignatureLen);
OUTPUT:
	RETVAL

# TODO: C_VerifyUpdate
# TODO: C_VerifyFinal
# TODO: C_VerifyRecoverInit
# TODO: C_VerifyRecover


################################################################################
#
# Dual-purpose cryptographic functions
#

# TODO: C_DigestEncryptUpdate
# TODO: C_DecryptDigestUpdate
# TODO: C_SignEncryptUpdate
# TODO: C_DecryptVerifyUpdate

################################################################################
#
# Key management functions
#

CK_RV
C_GenerateKeyPair(self,hSession,pMechanism, \
	pPublicKeyTemplate, \
	pPrivateKeyTemplate, \
	phPublicKey,phPrivateKey)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	AV*                   pMechanism
	CK_ATTRIBUTE_PTR      pPublicKeyTemplate
	CK_ATTRIBUTE_PTR      pPrivateKeyTemplate
	CK_OBJECT_HANDLE      phPublicKey
	CK_OBJECT_HANDLE      phPrivateKey
PREINIT:
	CK_ULONG pPublicKeyTemplate_count;
	CK_ULONG pPrivateKeyTemplate_count;
CODE:
	CK_MECHANISM _pMechanism;

	_pMechanism.mechanism = SvUV(*av_fetch(pMechanism, 0, 0));
	_pMechanism.pParameter = NULL_PTR;
	_pMechanism.ulParameterLen = 0; 

	RETVAL = self->function_list->C_GenerateKeyPair(
		hSession,
		&_pMechanism,
		pPublicKeyTemplate,
		pPublicKeyTemplate_count,
		pPrivateKeyTemplate,
		pPrivateKeyTemplate_count,
		&phPublicKey,
		&phPrivateKey
	);

	Safefree(pPublicKeyTemplate);
	Safefree(pPrivateKeyTemplate);
OUTPUT:
	RETVAL
	phPublicKey
	phPrivateKey


CK_RV
C_GenerateKey(self,hSession,pMechanism, \
	pTemplate, phKey)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	AV*                   pMechanism
	CK_ATTRIBUTE_PTR      pTemplate
	CK_OBJECT_HANDLE      phKey
PREINIT:
	CK_ULONG pTemplate_count;
CODE:
	CK_MECHANISM _pMechanism;

	_pMechanism.mechanism = SvUV(*av_fetch(pMechanism, 0, 0));
	_pMechanism.pParameter = NULL_PTR;
	_pMechanism.ulParameterLen = 0; 

	RETVAL = self->function_list->C_GenerateKey(
		hSession,
		&_pMechanism,
		pTemplate,
		pTemplate_count,
		&phKey
	);

	Safefree(pTemplate);
OUTPUT:
	RETVAL
	phKey


CK_RV
C_WrapKey(self,hSession,pMechanism, \
	hWrappingKey, hKey, pWrappedKey, ulWrappedKeyLen)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	AV*                   pMechanism
	CK_OBJECT_HANDLE      hWrappingKey
	CK_OBJECT_HANDLE      hKey
	SV*                   pWrappedKey
	CK_ULONG              ulWrappedKeyLen
CODE:
	CK_MECHANISM _pMechanism;

	_pMechanism.mechanism = SvUV(*av_fetch(pMechanism, 0, 0));
	_pMechanism.pParameter = NULL_PTR;
	_pMechanism.ulParameterLen = 0; 

	RETVAL = self->function_list->C_WrapKey(
		hSession,
		&_pMechanism,
		hWrappingKey,
		hKey,
		NULL_PTR,
		&ulWrappedKeyLen
	);

	if ( RETVAL==CKR_OK ) {
		CK_BYTE_PTR _pWrappedKey;
		Newx(_pWrappedKey,ulWrappedKeyLen,CK_BYTE);
		RETVAL = self->function_list->C_WrapKey(
			hSession,
			&_pMechanism,
			hWrappingKey,
			hKey,
			_pWrappedKey,
			&ulWrappedKeyLen
		);
		
		if ( RETVAL==CKR_OK ) {
			*pWrappedKey = *newSVpv((char*)_pWrappedKey, ulWrappedKeyLen);
		}
	}
OUTPUT:
	RETVAL
	pWrappedKey
	ulWrappedKeyLen

# TODO: C_UnwrapKey
# TODO: C_DeriveKey


################################################################################
#
# Random number generation functions
#

CK_RV
C_SeedRandom(self,hSession,pSeed,ulSeedLen)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	char*                 pSeed
	CK_ULONG              ulSeedLen
CODE:
	RETVAL = self->function_list->C_SeedRandom(hSession,(CK_BYTE_PTR)pSeed,ulSeedLen);
OUTPUT:
	RETVAL
	

CK_RV
C_GenerateRandom(self,hSession,pRandomData,ulRandomLen)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
	SV*                   pRandomData
	CK_ULONG              ulRandomLen
CODE:
	CK_BYTE_PTR _pRandomData;
	Newx(_pRandomData,ulRandomLen,CK_BYTE);
	RETVAL = self->function_list->C_GenerateRandom(hSession,_pRandomData,ulRandomLen);
	if ( RETVAL==CKR_OK ) {
		*pRandomData = *newSVpv((char*)_pRandomData, ulRandomLen);
	}
OUTPUT:
	RETVAL


################################################################################
#
# Parallel function management functions
#

CK_RV
C_GetFunctionStatus(self,hSession)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
CODE:
	RETVAL = self->function_list->C_GetFunctionStatus(hSession);
	// RETVAL = CKR_FUNCTION_NOT_PARALLEL;
OUTPUT:
	RETVAL

	
CK_RV
C_CancelFunction(self,hSession)
	Crypt::Cryptoki::Raw  self
	CK_SESSION_HANDLE     hSession
CODE:
	RETVAL = self->function_list->C_CancelFunction(hSession);
	// RETVAL = CKR_FUNCTION_NOT_PARALLEL;
OUTPUT:
	RETVAL
