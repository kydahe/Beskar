from Cryptodome.PublicKey import ECC

# generate server key
key = ECC.generate(curve='P-256')
f = open('server_key.pem', 'wt')
f.write(key.export_key(format='PEM'))
f.close()

# system-wide pk
key = ECC.generate(curve='P-256')
f = open('system_pk.pem', 'wt')
f.write(key.export_key(format='PEM'))
f.close()

# generate client keys
for i in range (2000):
	key = ECC.generate(curve='P-256')
	hdr = 'client'+str(i)+'.pem'
	f = open(hdr, 'wt')
	f.write(key.export_key(format='PEM'))
	f.close()
	pk_hdr = 'client'+str(i)+'_pk.pem'
	pf = open(pk_hdr, 'wt')
	pf.write(key.public_key().export_key(format='PEM'))
	pf.close()
	# with open(pk_hdr, "wbt") as f:
	# 	data = key.public_key().export_key()
	# 	f.write(data)

