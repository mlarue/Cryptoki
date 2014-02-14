#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "cryptoki/cryptoki.h"

#include "const-c.inc"

typedef CK_FUNCTION_LIST*        Crypt__Cryptoki__FunctionList;

MODULE = Crypt::Cryptoki::FunctionList		PACKAGE = Crypt::Cryptoki::FunctionList

INCLUDE: const-xs.inc

PROTOTYPES: ENABLE

CK_RV
C_Initialize(fl)
	Crypt::Cryptoki::FunctionList	fl
CODE:
	RETVAL = fl->C_Initialize(NULL);
OUTPUT:
	RETVAL
	

CK_RV
C_GetInfo(fl,info)
	Crypt::Cryptoki::FunctionList	fl
	HV*						info
CODE:
	CK_INFO _info;
	RETVAL = fl->C_GetInfo(&_info);
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


CK_RV
C_GetSlotList(fl,tokenPresent,pSlotList)
	Crypt::Cryptoki::FunctionList	fl
	CK_BBOOL 				tokenPresent
	AV*			 			pSlotList
CODE:
	CK_ULONG pulCount;

	RETVAL = fl->C_GetSlotList(tokenPresent,NULL_PTR,&pulCount);

	if ( RETVAL == CKR_OK ) {
		CK_SLOT_ID_PTR _pSlotList;
		Newxz(_pSlotList, pulCount, CK_SLOT_ID);

		RETVAL = fl->C_GetSlotList(tokenPresent,_pSlotList,&pulCount);

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
C_GetSlotInfo(fl,slotID,pInfo)
	Crypt::Cryptoki::FunctionList	fl
	CK_SLOT_ID				slotID
	HV*						pInfo
CODE:
	CK_SLOT_INFO _pInfo;
	RETVAL = fl->C_GetSlotInfo(slotID,&_pInfo);
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
C_GetTokenInfo(fl,slotID,pInfo)
	Crypt::Cryptoki::FunctionList	fl
	CK_SLOT_ID				slotID
	HV*						pInfo
CODE:
	CK_TOKEN_INFO _pInfo;
	RETVAL = fl->C_GetTokenInfo(slotID,&_pInfo);
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
C_OpenSession(fl,slotID,flags,phSession)
	Crypt::Cryptoki::FunctionList	fl
	CK_SLOT_ID 				slotID
	CK_FLAGS 				flags
//	CK_VOID_PTR 			pApplication
//	CK_NOTIFY 				Notify
	CK_SESSION_HANDLE	 	phSession
CODE:
	RETVAL = fl->C_OpenSession(slotID,flags,NULL_PTR,NULL_PTR,&phSession);
OUTPUT:
	RETVAL
	phSession


CK_RV
C_GetSessionInfo(fl,hSession,pInfo)
	Crypt::Cryptoki::FunctionList	fl
	CK_SESSION_HANDLE 		hSession
	HV* 					pInfo
CODE:
	CK_SESSION_INFO _pInfo;
	RETVAL = fl->C_GetSessionInfo(hSession,&_pInfo);
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
C_Login(fl,hSession,userType,pPin)
	Crypt::Cryptoki::FunctionList	fl
	CK_SESSION_HANDLE 		hSession
	CK_USER_TYPE 			userType
	CK_UTF8CHAR_PTR	 		pPin
CODE:
	CK_ULONG ulPinLen = strlen((const char *)pPin);
	RETVAL = fl->C_Login(hSession,userType,pPin,ulPinLen);
OUTPUT:
	RETVAL


CK_RV
C_GenerateKeyPair(fl,hSession,pMechanism, \
	pPublicKeyTemplate, \
	pPrivateKeyTemplate, \
	phPublicKey,phPrivateKey)
	Crypt::Cryptoki::FunctionList	fl
	CK_SESSION_HANDLE 		hSession
	AV*				 		pMechanism
	AV* 					pPublicKeyTemplate
	AV* 					pPrivateKeyTemplate
	CK_OBJECT_HANDLE	 	phPublicKey
	CK_OBJECT_HANDLE		phPrivateKey
CODE:
	CK_MECHANISM	 		_pMechanism;
	CK_ATTRIBUTE_PTR 		_pPublicKeyTemplate;
	CK_ULONG 				ulPublicKeyAttributeCount = 0;
	CK_ATTRIBUTE_PTR 		_pPrivateKeyTemplate;
	CK_ULONG 				ulPrivateKeyAttributeCount = 0;

	_pMechanism.mechanism = SvUV(*av_fetch(pMechanism, 0, 0));
	_pMechanism.pParameter = NULL_PTR;
	_pMechanism.ulParameterLen = 0; 

	Newxz(_pPublicKeyTemplate, av_top_index(pPublicKeyTemplate)+1, CK_ATTRIBUTE);
	int i = 0;
	for(i=0;i<=av_top_index(pPublicKeyTemplate);++i){
		SV** elem = av_fetch(pPublicKeyTemplate, i, 0);
		if ( elem != NULL ) {
			AV* attr = (AV*)SvRV(*elem);
			// TODO: check if attr is AV*
			// TODO: length check

			_pPublicKeyTemplate[i].type = SvUV(*av_fetch(attr, 0, 0));

			SV* _value = *av_fetch(attr, 1, 0);
			CK_ULONG _len = sv_len(_value);

			_pPublicKeyTemplate[i].pValue = (void*)SvPV(_value, _len);
			_pPublicKeyTemplate[i].ulValueLen = _len;

			ulPublicKeyAttributeCount++;
		}
	}

	Newxz(_pPrivateKeyTemplate, av_top_index(pPrivateKeyTemplate)+1, CK_ATTRIBUTE);
	for(i=0;i<=av_top_index(pPrivateKeyTemplate);++i){
		SV** elem = av_fetch(pPrivateKeyTemplate, i, 0);
		if ( elem != NULL ) {
			AV* attr = (AV*)SvRV(*elem);

			_pPrivateKeyTemplate[i].type = SvUV(*av_fetch(attr, 0, 0));

			SV* _value = *av_fetch(attr, 1, 0);
			CK_ULONG _len = sv_len(_value);

			_pPrivateKeyTemplate[i].pValue = (void*)SvPV(_value, _len);
			_pPrivateKeyTemplate[i].ulValueLen = _len;

			ulPrivateKeyAttributeCount++;
		}
	}

	RETVAL = fl->C_GenerateKeyPair(hSession,&_pMechanism,
		_pPublicKeyTemplate,ulPublicKeyAttributeCount,
		_pPrivateKeyTemplate,ulPrivateKeyAttributeCount,
		&phPublicKey,&phPrivateKey);

	Safefree(_pPublicKeyTemplate);
	Safefree(_pPrivateKeyTemplate);
OUTPUT:
	RETVAL
	phPublicKey
	phPrivateKey



CK_RV
C_EncryptInit(fl,hSession,pMechanism,hKey)
	Crypt::Cryptoki::FunctionList	fl
	CK_SESSION_HANDLE 		hSession
	AV*				 		pMechanism
	CK_OBJECT_HANDLE 		hKey
CODE:
	CK_MECHANISM	 		_pMechanism;
	_pMechanism.mechanism = SvUV(*av_fetch(pMechanism, 0, 0));
	_pMechanism.pParameter = NULL_PTR;
	_pMechanism.ulParameterLen = 0; 
	RETVAL = fl->C_EncryptInit(hSession,&_pMechanism,hKey);
OUTPUT:
	RETVAL




CK_RV
C_Encrypt(fl,hSession,pData,ulDataLen,pEncryptedData,ulEncryptedDataLen)
	Crypt::Cryptoki::FunctionList	fl
	CK_SESSION_HANDLE 		hSession
	char* 					pData
	CK_ULONG				ulDataLen
	SV* 					pEncryptedData
	CK_ULONG				ulEncryptedDataLen
CODE:
	RETVAL = fl->C_Encrypt(hSession,(CK_BYTE_PTR)pData,ulDataLen,
		NULL_PTR,&ulEncryptedDataLen);
	if ( RETVAL==CKR_OK ) {
		CK_BYTE_PTR _pEncryptedData;
		Newx(_pEncryptedData,ulEncryptedDataLen,CK_BYTE);
		RETVAL = fl->C_Encrypt(hSession,(CK_BYTE_PTR)pData,ulDataLen,
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
C_DecryptInit(fl,hSession,pMechanism,hKey)
	Crypt::Cryptoki::FunctionList	fl
	CK_SESSION_HANDLE 		hSession
	AV*				 		pMechanism
	CK_OBJECT_HANDLE 		hKey
CODE:
	CK_MECHANISM	 		_pMechanism;
	_pMechanism.mechanism = SvUV(*av_fetch(pMechanism, 0, 0));
	_pMechanism.pParameter = NULL_PTR;
	_pMechanism.ulParameterLen = 0; 
	RETVAL = fl->C_DecryptInit(hSession,&_pMechanism,hKey);
OUTPUT:
	RETVAL



CK_RV
C_Decrypt(fl,hSession,pEncryptedData,ulEncryptedDataLen,pData,ulDataLen)
	Crypt::Cryptoki::FunctionList	fl
	CK_SESSION_HANDLE 		hSession
	char* 					pEncryptedData
	CK_ULONG				ulEncryptedDataLen
	SV* 					pData
	CK_ULONG				ulDataLen
CODE:
	RETVAL = fl->C_Decrypt(hSession,(CK_BYTE_PTR)pEncryptedData,ulEncryptedDataLen,
		NULL_PTR,&ulDataLen);
	if ( RETVAL==CKR_OK ) {
		CK_BYTE_PTR _pData;
		Newx(_pData,ulDataLen,CK_BYTE);
		RETVAL = fl->C_Decrypt(hSession,(CK_BYTE_PTR)pEncryptedData,ulEncryptedDataLen,
			_pData,&ulDataLen);

		if ( RETVAL==CKR_OK ) {
			*pData = *newSVpv((char*)_pData, ulDataLen);
		}
	}
OUTPUT:
	RETVAL
	pData
	ulDataLen



CK_RV
C_SignInit(fl,hSession,pMechanism,hKey)
	Crypt::Cryptoki::FunctionList	fl
	CK_SESSION_HANDLE 		hSession
	AV*				 		pMechanism
	CK_OBJECT_HANDLE 		hKey
CODE:
	CK_MECHANISM	 		_pMechanism;
	_pMechanism.mechanism = SvUV(*av_fetch(pMechanism, 0, 0));
	_pMechanism.pParameter = NULL_PTR;
	_pMechanism.ulParameterLen = 0; 
	RETVAL = fl->C_SignInit(hSession,&_pMechanism,hKey);
OUTPUT:
	RETVAL



CK_RV
C_Sign(fl,hSession,pData,ulDataLen,pSignature,ulSignatureLen)
	Crypt::Cryptoki::FunctionList	fl
	CK_SESSION_HANDLE 		hSession
	char* 					pData
	CK_ULONG				ulDataLen
	SV* 					pSignature
	CK_ULONG				ulSignatureLen
CODE:
	RETVAL = fl->C_Sign(hSession,(CK_BYTE_PTR)pData,ulDataLen,
		NULL_PTR,&ulSignatureLen);
	if ( RETVAL==CKR_OK ) {
		CK_BYTE_PTR _pSignature;
		Newx(_pSignature,ulSignatureLen,CK_BYTE);
		RETVAL = fl->C_Sign(hSession,(CK_BYTE_PTR)pData,ulDataLen,
			_pSignature,&ulSignatureLen);

		if ( RETVAL==CKR_OK ) {
			*pSignature = *newSVpv((char*)_pSignature, ulSignatureLen);
		}
	}
OUTPUT:
	RETVAL
	pSignature
	ulSignatureLen



CK_RV
C_VerifyInit(fl,hSession,pMechanism,hKey)
	Crypt::Cryptoki::FunctionList	fl
	CK_SESSION_HANDLE 		hSession
	AV*				 		pMechanism
	CK_OBJECT_HANDLE 		hKey
CODE:
	CK_MECHANISM	 		_pMechanism;
	_pMechanism.mechanism = SvUV(*av_fetch(pMechanism, 0, 0));
	_pMechanism.pParameter = NULL_PTR;
	_pMechanism.ulParameterLen = 0; 
	RETVAL = fl->C_VerifyInit(hSession,&_pMechanism,hKey);
OUTPUT:
	RETVAL



CK_RV
C_Verify(fl,hSession,pData,ulDataLen,pSignature,ulSignatureLen)
	Crypt::Cryptoki::FunctionList	fl
	CK_SESSION_HANDLE 		hSession
	char* 					pData
	CK_ULONG				ulDataLen
	char* 					pSignature
	CK_ULONG				ulSignatureLen
CODE:
	RETVAL = fl->C_Verify(hSession,(CK_BYTE_PTR)pData,ulDataLen,
		(CK_BYTE_PTR)pSignature,ulSignatureLen);
OUTPUT:
	RETVAL




CK_RV
C_DestroyObject(fl,hSession,hObject)
	Crypt::Cryptoki::FunctionList	fl
	CK_SESSION_HANDLE 		hSession
	CK_OBJECT_HANDLE 		hObject
CODE:
	RETVAL = fl->C_DestroyObject(hSession,hObject);
OUTPUT:
	RETVAL



