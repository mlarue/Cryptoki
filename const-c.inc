#define PERL_constant_NOTFOUND	1
#define PERL_constant_NOTDEF	2
#define PERL_constant_ISIV	3
#define PERL_constant_ISNO	4
#define PERL_constant_ISNV	5
#define PERL_constant_ISPV	6
#define PERL_constant_ISPVN	7
#define PERL_constant_ISSV	8
#define PERL_constant_ISUNDEF	9
#define PERL_constant_ISUV	10
#define PERL_constant_ISYES	11

#ifndef NVTYPE
typedef double NV; /* 5.6 and later define NVTYPE, and typedef NV to it.  */
#endif
#ifndef aTHX_
#define aTHX_ /* 5.6 or later define this for threading support.  */
#endif
#ifndef pTHX_
#define pTHX_ /* 5.6 or later define this for threading support.  */
#endif

static int
constant_6 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CKA_ID CKR_OK CKU_SO */
  /* Offset 4 gives the best switch position.  */
  switch (name[4]) {
  case 'I':
    if (memEQ(name, "CKA_ID", 6)) {
    /*                   ^       */
#ifdef CKA_ID
      *iv_return = CKA_ID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "CKR_OK", 6)) {
    /*                   ^       */
#ifdef CKR_OK
      *iv_return = CKR_OK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "CKU_SO", 6)) {
    /*                   ^       */
#ifdef CKU_SO
      *iv_return = CKU_SO;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_8 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CKA_SIGN CKA_WRAP CKU_USER NULL_PTR */
  /* Offset 5 gives the best switch position.  */
  switch (name[5]) {
  case 'I':
    if (memEQ(name, "CKA_SIGN", 8)) {
    /*                    ^        */
#ifdef CKA_SIGN
      *iv_return = CKA_SIGN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "NULL_PTR", 8)) {
    /*                    ^        */
#ifdef NULL_PTR
      *iv_return = NULL_PTR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "CKA_WRAP", 8)) {
    /*                    ^        */
#ifdef CKA_WRAP
      *iv_return = CKA_WRAP;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "CKU_USER", 8)) {
    /*                    ^        */
#ifdef CKU_USER
      *iv_return = CKU_USER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_9 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CKA_CLASS CKA_LABEL CKA_TOKEN */
  /* Offset 8 gives the best switch position.  */
  switch (name[8]) {
  case 'L':
    if (memEQ(name, "CKA_LABE", 8)) {
    /*                       L     */
#ifdef CKA_LABEL
      *iv_return = CKA_LABEL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "CKA_TOKE", 8)) {
    /*                       N     */
#ifdef CKA_TOKEN
      *iv_return = CKA_TOKEN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "CKA_CLAS", 8)) {
    /*                       S     */
#ifdef CKA_CLASS
      *iv_return = CKA_CLASS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_11 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CKA_DECRYPT CKA_ENCRYPT CKA_PRIVATE */
  /* Offset 4 gives the best switch position.  */
  switch (name[4]) {
  case 'D':
    if (memEQ(name, "CKA_DECRYPT", 11)) {
    /*                   ^             */
#ifdef CKA_DECRYPT
      *iv_return = CKA_DECRYPT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "CKA_ENCRYPT", 11)) {
    /*                   ^             */
#ifdef CKA_ENCRYPT
      *iv_return = CKA_ENCRYPT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "CKA_PRIVATE", 11)) {
    /*                   ^             */
#ifdef CKA_PRIVATE
      *iv_return = CKA_PRIVATE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_15 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CKO_PRIVATE_KEY CKR_HOST_MEMORY CKR_PIN_EXPIRED */
  /* Offset 12 gives the best switch position.  */
  switch (name[12]) {
  case 'K':
    if (memEQ(name, "CKO_PRIVATE_KEY", 15)) {
    /*                           ^         */
#ifdef CKO_PRIVATE_KEY
      *iv_return = CKO_PRIVATE_KEY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "CKR_HOST_MEMORY", 15)) {
    /*                           ^         */
#ifdef CKR_HOST_MEMORY
      *iv_return = CKR_HOST_MEMORY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "CKR_PIN_EXPIRED", 15)) {
    /*                           ^         */
#ifdef CKR_PIN_EXPIRED
      *iv_return = CKR_PIN_EXPIRED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_16 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CKA_MODULUS_BITS CKR_DEVICE_ERROR CK_NEED_ARG_LIST */
  /* Offset 15 gives the best switch position.  */
  switch (name[15]) {
  case 'R':
    if (memEQ(name, "CKR_DEVICE_ERRO", 15)) {
    /*                              R      */
#ifdef CKR_DEVICE_ERROR
      *iv_return = CKR_DEVICE_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "CKA_MODULUS_BIT", 15)) {
    /*                              S      */
#ifdef CKA_MODULUS_BITS
      *iv_return = CKA_MODULUS_BITS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "CK_NEED_ARG_LIS", 15)) {
    /*                              T      */
#ifdef CK_NEED_ARG_LIST
      *iv_return = CK_NEED_ARG_LIST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_17 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CKR_ARGUMENTS_BAD CKR_DEVICE_MEMORY CKR_GENERAL_ERROR CKR_PIN_INCORRECT */
  /* Offset 4 gives the best switch position.  */
  switch (name[4]) {
  case 'A':
    if (memEQ(name, "CKR_ARGUMENTS_BAD", 17)) {
    /*                   ^                   */
#ifdef CKR_ARGUMENTS_BAD
      *iv_return = CKR_ARGUMENTS_BAD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "CKR_DEVICE_MEMORY", 17)) {
    /*                   ^                   */
#ifdef CKR_DEVICE_MEMORY
      *iv_return = CKR_DEVICE_MEMORY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "CKR_GENERAL_ERROR", 17)) {
    /*                   ^                   */
#ifdef CKR_GENERAL_ERROR
      *iv_return = CKR_GENERAL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "CKR_PIN_INCORRECT", 17)) {
    /*                   ^                   */
#ifdef CKR_PIN_INCORRECT
      *iv_return = CKR_PIN_INCORRECT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_18 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CKF_SERIAL_SESSION CKR_DEVICE_REMOVED CKR_SESSION_CLOSED */
  /* Offset 6 gives the best switch position.  */
  switch (name[6]) {
  case 'R':
    if (memEQ(name, "CKF_SERIAL_SESSION", 18)) {
    /*                     ^                  */
#ifdef CKF_SERIAL_SESSION
      *iv_return = CKF_SERIAL_SESSION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "CKR_SESSION_CLOSED", 18)) {
    /*                     ^                  */
#ifdef CKR_SESSION_CLOSED
      *iv_return = CKR_SESSION_CLOSED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'V':
    if (memEQ(name, "CKR_DEVICE_REMOVED", 18)) {
    /*                     ^                  */
#ifdef CKR_DEVICE_REMOVED
      *iv_return = CKR_DEVICE_REMOVED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_19 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CKA_PUBLIC_EXPONENT CKR_FUNCTION_FAILED CKS_RW_SO_FUNCTIONS */
  /* Offset 16 gives the best switch position.  */
  switch (name[16]) {
  case 'E':
    if (memEQ(name, "CKA_PUBLIC_EXPONENT", 19)) {
    /*                               ^         */
#ifdef CKA_PUBLIC_EXPONENT
      *iv_return = CKA_PUBLIC_EXPONENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "CKR_FUNCTION_FAILED", 19)) {
    /*                               ^         */
#ifdef CKR_FUNCTION_FAILED
      *iv_return = CKR_FUNCTION_FAILED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "CKS_RW_SO_FUNCTIONS", 19)) {
    /*                               ^         */
#ifdef CKS_RW_SO_FUNCTIONS
      *iv_return = CKS_RW_SO_FUNCTIONS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_21 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CKR_FUNCTION_CANCELED CKR_MECHANISM_INVALID CKR_SESSION_READ_ONLY
     CKS_RO_PUBLIC_SESSION CKS_RO_USER_FUNCTIONS CKS_RW_PUBLIC_SESSION
     CKS_RW_USER_FUNCTIONS */
  /* Offset 10 gives the best switch position.  */
  switch (name[10]) {
  case 'I':
    if (memEQ(name, "CKR_MECHANISM_INVALID", 21)) {
    /*                         ^                 */
#ifdef CKR_MECHANISM_INVALID
      *iv_return = CKR_MECHANISM_INVALID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "CKS_RO_PUBLIC_SESSION", 21)) {
    /*                         ^                 */
#ifdef CKS_RO_PUBLIC_SESSION
      *iv_return = CKS_RO_PUBLIC_SESSION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "CKS_RW_PUBLIC_SESSION", 21)) {
    /*                         ^                 */
#ifdef CKS_RW_PUBLIC_SESSION
      *iv_return = CKS_RW_PUBLIC_SESSION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "CKR_SESSION_READ_ONLY", 21)) {
    /*                         ^                 */
#ifdef CKR_SESSION_READ_ONLY
      *iv_return = CKR_SESSION_READ_ONLY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "CKR_FUNCTION_CANCELED", 21)) {
    /*                         ^                 */
#ifdef CKR_FUNCTION_CANCELED
      *iv_return = CKR_FUNCTION_CANCELED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "CKS_RO_USER_FUNCTIONS", 21)) {
    /*                         ^                 */
#ifdef CKS_RO_USER_FUNCTIONS
      *iv_return = CKS_RO_USER_FUNCTIONS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "CKS_RW_USER_FUNCTIONS", 21)) {
    /*                         ^                 */
#ifdef CKS_RW_USER_FUNCTIONS
      *iv_return = CKS_RW_USER_FUNCTIONS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_25 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CKM_RSA_PKCS_KEY_PAIR_GEN CKR_DOMAIN_PARAMS_INVALID
     CKR_TEMPLATE_INCONSISTENT CKR_TOKEN_WRITE_PROTECTED */
  /* Offset 8 gives the best switch position.  */
  switch (name[8]) {
  case 'I':
    if (memEQ(name, "CKR_DOMAIN_PARAMS_INVALID", 25)) {
    /*                       ^                       */
#ifdef CKR_DOMAIN_PARAMS_INVALID
      *iv_return = CKR_DOMAIN_PARAMS_INVALID;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "CKR_TEMPLATE_INCONSISTENT", 25)) {
    /*                       ^                       */
#ifdef CKR_TEMPLATE_INCONSISTENT
      *iv_return = CKR_TEMPLATE_INCONSISTENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "CKR_TOKEN_WRITE_PROTECTED", 25)) {
    /*                       ^                       */
#ifdef CKR_TOKEN_WRITE_PROTECTED
      *iv_return = CKR_TOKEN_WRITE_PROTECTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "CKM_RSA_PKCS_KEY_PAIR_GEN", 25)) {
    /*                       ^                       */
#ifdef CKM_RSA_PKCS_KEY_PAIR_GEN
      *iv_return = CKM_RSA_PKCS_KEY_PAIR_GEN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant (pTHX_ const char *name, STRLEN len, IV *iv_return) {
  /* Initially switch on the length of the name.  */
  /* When generated this function returned values for the list of names given
     in this section of perl code.  Rather than manually editing these functions
     to add or remove constants, which would result in this comment and section
     of code becoming inaccurate, we recommend that you edit this section of
     code, and use it to regenerate a new set of constant functions which you
     then use to replace the originals.

     Regenerate these constant functions by feeding this entire source file to
     perl -x

#!/usr/bin/perl -w
use ExtUtils::Constant qw (constant_types C_constant XS_constant);

my $types = {map {($_, 1)} qw(IV)};
my @names = (qw(CKA_CLASS CKA_DECRYPT CKA_ENCRYPT CKA_ID CKA_KEY_TYPE CKA_LABEL
	       CKA_MODULUS_BITS CKA_PRIVATE CKA_PUBLIC_EXPONENT CKA_SENSITIVE
	       CKA_SIGN CKA_TOKEN CKA_UNWRAP CKA_VERIFY CKA_WRAP CKF_RW_SESSION
	       CKF_SERIAL_SESSION CKK_RSA CKM_RSA_PKCS
	       CKM_RSA_PKCS_KEY_PAIR_GEN CKO_PRIVATE_KEY CKO_PUBLIC_KEY
	       CKR_ARGUMENTS_BAD CKR_ATTRIBUTE_READ_ONLY
	       CKR_ATTRIBUTE_TYPE_INVALID CKR_ATTRIBUTE_VALUE_INVALID
	       CKR_CRYPTOKI_NOT_INITIALIZED CKR_DEVICE_ERROR CKR_DEVICE_MEMORY
	       CKR_DEVICE_REMOVED CKR_DOMAIN_PARAMS_INVALID
	       CKR_FUNCTION_CANCELED CKR_FUNCTION_FAILED CKR_GENERAL_ERROR
	       CKR_HOST_MEMORY CKR_MECHANISM_INVALID
	       CKR_MECHANISM_PARAM_INVALID CKR_OK CKR_OPERATION_ACTIVE
	       CKR_PIN_EXPIRED CKR_PIN_INCORRECT CKR_SESSION_CLOSED
	       CKR_SESSION_HANDLE_INVALID CKR_SESSION_READ_ONLY
	       CKR_SESSION_READ_ONLY_EXISTS CKR_TEMPLATE_INCOMPLETE
	       CKR_TEMPLATE_INCONSISTENT CKR_TOKEN_WRITE_PROTECTED
	       CKR_USER_NOT_LOGGED_IN CKS_RO_PUBLIC_SESSION
	       CKS_RO_USER_FUNCTIONS CKS_RW_PUBLIC_SESSION CKS_RW_SO_FUNCTIONS
	       CKS_RW_USER_FUNCTIONS CKU_SO CKU_USER CK_NEED_ARG_LIST NULL_PTR
	       TRUE));

print constant_types(), "\n"; # macro defs
foreach (C_constant ("Cryptoki", 'constant', 'IV', $types, undef, 3, @names) ) {
    print $_, "\n"; # C constant subs
}
print "\n#### XS Section:\n";
print XS_constant ("Cryptoki", $types);
__END__
   */

  switch (len) {
  case 4:
    if (memEQ(name, "TRUE", 4)) {
#ifdef TRUE
      *iv_return = TRUE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 6:
    return constant_6 (aTHX_ name, iv_return);
    break;
  case 7:
    if (memEQ(name, "CKK_RSA", 7)) {
#ifdef CKK_RSA
      *iv_return = CKK_RSA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 8:
    return constant_8 (aTHX_ name, iv_return);
    break;
  case 9:
    return constant_9 (aTHX_ name, iv_return);
    break;
  case 10:
    /* Names all of length 10.  */
    /* CKA_UNWRAP CKA_VERIFY */
    /* Offset 4 gives the best switch position.  */
    switch (name[4]) {
    case 'U':
      if (memEQ(name, "CKA_UNWRAP", 10)) {
      /*                   ^            */
#ifdef CKA_UNWRAP
        *iv_return = CKA_UNWRAP;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'V':
      if (memEQ(name, "CKA_VERIFY", 10)) {
      /*                   ^            */
#ifdef CKA_VERIFY
        *iv_return = CKA_VERIFY;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 11:
    return constant_11 (aTHX_ name, iv_return);
    break;
  case 12:
    /* Names all of length 12.  */
    /* CKA_KEY_TYPE CKM_RSA_PKCS */
    /* Offset 8 gives the best switch position.  */
    switch (name[8]) {
    case 'P':
      if (memEQ(name, "CKM_RSA_PKCS", 12)) {
      /*                       ^          */
#ifdef CKM_RSA_PKCS
        *iv_return = CKM_RSA_PKCS;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'T':
      if (memEQ(name, "CKA_KEY_TYPE", 12)) {
      /*                       ^          */
#ifdef CKA_KEY_TYPE
        *iv_return = CKA_KEY_TYPE;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 13:
    if (memEQ(name, "CKA_SENSITIVE", 13)) {
#ifdef CKA_SENSITIVE
      *iv_return = CKA_SENSITIVE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 14:
    /* Names all of length 14.  */
    /* CKF_RW_SESSION CKO_PUBLIC_KEY */
    /* Offset 4 gives the best switch position.  */
    switch (name[4]) {
    case 'P':
      if (memEQ(name, "CKO_PUBLIC_KEY", 14)) {
      /*                   ^                */
#ifdef CKO_PUBLIC_KEY
        *iv_return = CKO_PUBLIC_KEY;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'R':
      if (memEQ(name, "CKF_RW_SESSION", 14)) {
      /*                   ^                */
#ifdef CKF_RW_SESSION
        *iv_return = CKF_RW_SESSION;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 15:
    return constant_15 (aTHX_ name, iv_return);
    break;
  case 16:
    return constant_16 (aTHX_ name, iv_return);
    break;
  case 17:
    return constant_17 (aTHX_ name, iv_return);
    break;
  case 18:
    return constant_18 (aTHX_ name, iv_return);
    break;
  case 19:
    return constant_19 (aTHX_ name, iv_return);
    break;
  case 20:
    if (memEQ(name, "CKR_OPERATION_ACTIVE", 20)) {
#ifdef CKR_OPERATION_ACTIVE
      *iv_return = CKR_OPERATION_ACTIVE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 21:
    return constant_21 (aTHX_ name, iv_return);
    break;
  case 22:
    if (memEQ(name, "CKR_USER_NOT_LOGGED_IN", 22)) {
#ifdef CKR_USER_NOT_LOGGED_IN
      *iv_return = CKR_USER_NOT_LOGGED_IN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 23:
    /* Names all of length 23.  */
    /* CKR_ATTRIBUTE_READ_ONLY CKR_TEMPLATE_INCOMPLETE */
    /* Offset 9 gives the best switch position.  */
    switch (name[9]) {
    case 'A':
      if (memEQ(name, "CKR_TEMPLATE_INCOMPLETE", 23)) {
      /*                        ^                    */
#ifdef CKR_TEMPLATE_INCOMPLETE
        *iv_return = CKR_TEMPLATE_INCOMPLETE;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'B':
      if (memEQ(name, "CKR_ATTRIBUTE_READ_ONLY", 23)) {
      /*                        ^                    */
#ifdef CKR_ATTRIBUTE_READ_ONLY
        *iv_return = CKR_ATTRIBUTE_READ_ONLY;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 25:
    return constant_25 (aTHX_ name, iv_return);
    break;
  case 26:
    /* Names all of length 26.  */
    /* CKR_ATTRIBUTE_TYPE_INVALID CKR_SESSION_HANDLE_INVALID */
    /* Offset 6 gives the best switch position.  */
    switch (name[6]) {
    case 'S':
      if (memEQ(name, "CKR_SESSION_HANDLE_INVALID", 26)) {
      /*                     ^                          */
#ifdef CKR_SESSION_HANDLE_INVALID
        *iv_return = CKR_SESSION_HANDLE_INVALID;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'T':
      if (memEQ(name, "CKR_ATTRIBUTE_TYPE_INVALID", 26)) {
      /*                     ^                          */
#ifdef CKR_ATTRIBUTE_TYPE_INVALID
        *iv_return = CKR_ATTRIBUTE_TYPE_INVALID;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 27:
    /* Names all of length 27.  */
    /* CKR_ATTRIBUTE_VALUE_INVALID CKR_MECHANISM_PARAM_INVALID */
    /* Offset 11 gives the best switch position.  */
    switch (name[11]) {
    case 'S':
      if (memEQ(name, "CKR_MECHANISM_PARAM_INVALID", 27)) {
      /*                          ^                      */
#ifdef CKR_MECHANISM_PARAM_INVALID
        *iv_return = CKR_MECHANISM_PARAM_INVALID;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'T':
      if (memEQ(name, "CKR_ATTRIBUTE_VALUE_INVALID", 27)) {
      /*                          ^                      */
#ifdef CKR_ATTRIBUTE_VALUE_INVALID
        *iv_return = CKR_ATTRIBUTE_VALUE_INVALID;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 28:
    /* Names all of length 28.  */
    /* CKR_CRYPTOKI_NOT_INITIALIZED CKR_SESSION_READ_ONLY_EXISTS */
    /* Offset 7 gives the best switch position.  */
    switch (name[7]) {
    case 'P':
      if (memEQ(name, "CKR_CRYPTOKI_NOT_INITIALIZED", 28)) {
      /*                      ^                           */
#ifdef CKR_CRYPTOKI_NOT_INITIALIZED
        *iv_return = CKR_CRYPTOKI_NOT_INITIALIZED;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'S':
      if (memEQ(name, "CKR_SESSION_READ_ONLY_EXISTS", 28)) {
      /*                      ^                           */
#ifdef CKR_SESSION_READ_ONLY_EXISTS
        *iv_return = CKR_SESSION_READ_ONLY_EXISTS;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

