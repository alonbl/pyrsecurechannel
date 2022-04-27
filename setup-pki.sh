#!/bin/sh

export EASYRSA_KEY_SIZE=4096
export EASYRSA_CERT_EXPIRE=$((10*365))
export EASYRSA_CRL_DAYS=$((10*365))

mkdir pki-root
cd pki-root

/usr/share/easy-rsa/easyrsa --batch init-pki
/usr/share/easy-rsa/easyrsa --batch build-ca nopass

#
# We target windows users
# who cannot run this script
# unfortunately, everything goes into git
#
for d in pki/revoked/* pki/renewed/*; do
	touch "${d}/.keep"
done

[ -n "${SKIP_DH}" ] || /usr/share/easy-rsa/easyrsa --batch gen-dh

/usr/share/easy-rsa/easyrsa --batch --subject-alt-name=DNS:server1 build-server-full server1 nopass
/usr/share/easy-rsa/easyrsa --batch --subject-alt-name=URI:urn:test:client1 build-client-full client1 nopass
/usr/share/easy-rsa/easyrsa --batch --subject-alt-name=DNS:server1 build-server-full server1-revoked nopass
/usr/share/easy-rsa/easyrsa --batch --subject-alt-name=URI:urn:test:client1 build-client-full client1-revoked nopass


/usr/share/easy-rsa/easyrsa --batch revoke server1-revoked
/usr/share/easy-rsa/easyrsa --batch revoke client1-revoked
/usr/share/easy-rsa/easyrsa --batch gen-crl

mkdir store
find pki -name '*.crt' | while read f; do
	name=$(openssl x509 -noout -in "${f}" -subject | sed 's/.*CN = //')
	ln -s "../${f}" "store/${name}.crt"
	ln -s "../$(find pki -name "$(basename "${f}" | sed 's/\.crt/.key/')")" "store/${name}.key"
done

mkdir capath
ln -s ../pki/ca.crt capath/
ln -s ../pki/crl.pem capath/
c_rehash capath

#
# We target Windows users for example
# symlinks must be removed.
#
find capath store -type l | while read f; do
	cp --remove-destination "$(realpath "${f}")" "${f}"
done
