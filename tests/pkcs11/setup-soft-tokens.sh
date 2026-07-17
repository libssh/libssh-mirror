#!/bin/bash

# The client keys are stored in a soft token.

TESTDIR=$1
PRIVKEY=$2
OBJNAME=$3
TOKENLABEL=$3 # yeah. The same as object label
LOADPUBLIC=$4
SOFT_TOKEN_MODULE=$5
shift 5

PUBKEY="$PRIVKEY.pub"

echo "TESTDIR: $TESTDIR"
echo "PRIVKEY: $PRIVKEY"
echo "PUBKEY: $PUBKEY"
echo "OBJNAME: $OBJNAME"
echo "TOKENLABEL: $TOKENLABEL"
echo "LOADPUBLIC: $LOADPUBLIC"
echo "SOFT_TOKEN_MODULE: $SOFT_TOKEN_MODULE"

if echo "$SOFT_TOKEN_MODULE" | grep -q "kryoptic"; then
    export KRYOPTIC_CONF="$TESTDIR/kryoptic.conf"
    if [ ! -f "$KRYOPTIC_CONF" ]; then
        touch "$KRYOPTIC_CONF"
    fi
    # Kryoptic does not auto-create slots, so count existing ones in config to find the next free one
    FREE_SLOT=$(grep -c '^\[\[slots\]\]' "$KRYOPTIC_CONF")
    cat >>"$KRYOPTIC_CONF" <<EOF
[[slots]]
slot = $FREE_SLOT
dbtype = "sqlite"
dbargs = "$TESTDIR/$TOKENLABEL.sql"
EOF
    cat "$KRYOPTIC_CONF"
elif echo "$SOFT_TOKEN_MODULE" | grep -q "softhsm"; then
    export SOFTHSM2_CONF=$TESTDIR/softhsm.conf
    if [ ! -d "$TESTDIR/db" ]; then
        # Create temporary directory for tokens
        install -d -m 0755 "$TESTDIR/db"

        # Create SoftHSM configuration file
        cat >"$SOFTHSM2_CONF" <<EOF
directories.tokendir = $TESTDIR/db
objectstore.backend = file
log.level = DEBUG
# # The hashed ECDSA mechanisms wrongly do not support multi-part operations
# https://github.com/softhsm/SoftHSMv2/issues/842
slots.mechanisms = -CKM_ECDSA_SHA1,CKM_ECDSA_SHA224,CKM_ECDSA_SHA256,CKM_ECDSA_SHA384,CKM_ECDSA_SHA512
EOF
    fi
    # SoftHSM2 creates a new uninitialized slot after each init
    FREE_SLOT=$(pkcs11-tool --module "$SOFT_TOKEN_MODULE" --list-slots 2>/dev/null | awk '/Slot [0-9][0-9]*/{slot=$2} /uninitialized/{print slot; exit}')
    cat "$SOFTHSM2_CONF"
else
    echo "Unknown PKCS#11 soft token module: $SOFT_TOKEN_MODULE"
    exit 1
fi

#init -- each object will have its own token
cmd="pkcs11-tool --module $SOFT_TOKEN_MODULE --init-token --slot-index $FREE_SLOT --label $TOKENLABEL --init-pin --pin 1234 --so-pin 1234"
eval echo "$cmd"
out=$(eval "$cmd")
ret=$?
if [ $ret -ne 0 ]; then
    echo "Init token failed"
    echo "$out"
    exit 1
fi

#load private key
cmd="p11tool --provider $SOFT_TOKEN_MODULE --write --load-privkey $PRIVKEY --label $OBJNAME --login --set-pin=1234 \"pkcs11:token=$TOKENLABEL\""
eval echo "$cmd"
out=$(eval "$cmd")
ret=$?
if [ $ret -ne 0 ]; then
   echo "Loading privkey failed"
   echo "$out"
   exit 1
fi

cat "$PUBKEY"

ls -l "$TESTDIR"

if [ "$LOADPUBLIC" -ne 0 ]; then
#load public key
    cmd="p11tool --provider $SOFT_TOKEN_MODULE --write --load-pubkey $PUBKEY --label $OBJNAME --login --set-pin=1234 \"pkcs11:token=$TOKENLABEL\""
    eval echo "$cmd"
    out=$(eval "$cmd")
    ret=$?
    if [ $ret -ne 0 ]; then
        echo "Loading pubkey failed"
        echo "$out"
        exit 1
    fi
fi

cmd="p11tool --list-all --login \"pkcs11:token=$TOKENLABEL\" --set-pin=1234"
eval echo "$cmd"
out=$(eval "$cmd")
ret=$?
if [ $ret -ne 0 ]; then
    echo "Logging in failed"
    echo "$out"
    exit 1
fi
echo "$out"

pkcs11-tool -M --login --pin=1234 --module="$SOFT_TOKEN_MODULE" --token-label="$TOKENLABEL"

exit 0
