"""Specified BitLocker v2 containers, encrypted independently with OpenSSL via
cryptography. Test credentials/keys are public constants, never user secrets.
"""
import gzip,hashlib,json,struct as s,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'target/crypto-oracle'))
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'tests/fixtures/forensics'
GUID=bytes.fromhex('3bd66749292ed84a8399f6a339e3d001')
def p16(d,o,v):s.pack_into('<H',d,o,v)
def p32(d,o,v):s.pack_into('<I',d,o,v)
def p64(d,o,v):s.pack_into('<Q',d,o,v)
def entry(kind,value,data):return s.pack('<HHHH',len(data)+8,kind,value,1)+data
def key_blob(method,key):return s.pack('<IHHI',len(key)+12,1,0,method)+key
def sealed(key,nonce,plaintext):
 data=AESCCM(key).encrypt(nonce,plaintext,None);return nonce+data[-16:]+data[:-16]
def stretch(initial,salt):
 last=bytes(32)
 for i in range(0x100000):last=hashlib.sha256(last+initial+salt+s.pack('<Q',i)).digest()
 return last
def encrypt_sector(method,key,at,plain):
 n=16 if method in [0x8000,0x8002] else 32
 if method>=0x8004:
  return Cipher(algorithms.AES(key),modes.XTS((at//512).to_bytes(16,'little'))).encryptor().update(plain)
 iv=Cipher(algorithms.AES(key[:n]),modes.ECB()).encryptor().update(at.to_bytes(16,'little'))
 if method<=0x8001:
  tweak=key[32:32+n];ecb=Cipher(algorithms.AES(tweak),modes.ECB()).encryptor();mask=ecb.update(at.to_bytes(16,'little')+(at+(0x80<<120)).to_bytes(16,'little'))
  words=list(s.unpack('<128I',bytes(b^mask[i%32] for i,b in enumerate(plain))))
  rol=lambda v,n:((v<<n)|(v>>(32-n if n else 32)))&0xffffffff
  for rounds,delta,rotation in [(5,-1,[9,0,13,0]),(3,1,[0,10,0,25])]:
   for _ in range(rounds):
    for i in reversed(range(128)):words[i]=(words[i]-(words[(i+delta*2)%128]^rol(words[(i+delta*5)%128],rotation[i%4])))&0xffffffff
  plain=s.pack('<128I',*words)
 return Cipher(algorithms.AES(key[:n]),modes.CBC(iv)).encryptor().update(plain)
def main():
 source=gzip.decompress((ROOT/'tests/fixtures/layers/ntfs.raw.gz').read_bytes());size=len(source);locations=[848*4096,880*4096,912*4096];header_at=960*4096
 password='fixture-password';recovery='-'.join(['000000']*8);vmk=bytes([0x56])*32;clear=bytes([0x11])*32;salt=bytes(range(16))
 recovery_key=stretch(hashlib.sha256(bytes(16)).digest(),salt)
 password_key=stretch(hashlib.sha256(hashlib.sha256(password.encode('utf-16le')).digest()).digest(),salt)
 records={}
 for method in range(0x8000,0x8006):
  length={0x8000:64,0x8001:64,0x8002:16,0x8003:32,0x8004:32,0x8005:64}[method];key=bytes((i+method)%256 for i in range(length))
  payload=entry(15,15,s.pack('<QQ',header_at,8192))
  for index,(protection,protector_key) in enumerate([(0x800,recovery_key),(0x2000,password_key),(0,clear)]):
   props=entry(0,1,s.pack('<I',0x2000)+clear) if protection==0 else entry(0,3,s.pack('<I',0x1000)+salt)
   props+=entry(0,5,sealed(protector_key,bytes([index+1])*12,key_blob(0x2000,vmk)))
   payload+=entry(2,8,bytes([index])*16+bytes(8)+s.pack('<HH',0,protection)+props)
  payload+=entry(3,5,sealed(vmk,bytes([4])*12,key_blob(method,key)))
  metadata=bytearray(48);p32(metadata,0,len(payload)+48);p32(metadata,4,1);p32(metadata,8,48);p32(metadata,12,len(payload)+48);metadata[16:32]=bytes([0x75])*16;p32(metadata,36,method);metadata+=payload
  block=bytearray(64);block[:8]=b'-FVE-FS-';p16(block,8,(64+len(metadata)+15)//16);p16(block,10,2);p16(block,12,4);p16(block,14,4);p64(block,16,size);p32(block,28,16)
  for i,at in enumerate(locations):p64(block,32+i*8,at)
  p64(block,56,header_at);block+=metadata
  encrypted=bytearray(size)
  for at in range(0,size,512):encrypted[at:at+512]=encrypt_sector(method,key,at,source[at:at+512])
  for at in range(0,8192,512):encrypted[header_at+at:header_at+at+512]=encrypt_sector(method,key,header_at+at,source[at:at+512])
  boot=bytearray(512);boot[:3]=b'\xeb\x58\x90';boot[3:11]=b'-FVE-FS-';p16(boot,11,512);boot[160:176]=GUID
  for i,at in enumerate(locations):p64(boot,176+i*8,at)
  boot[510:]=b'\x55\xaa';encrypted[:512]=boot
  expected=bytearray(source)
  for at in locations:encrypted[at:at+len(block)]=block;expected[at:at+65536]=bytes(65536)
  expected[header_at:header_at+8192]=bytes(8192)
  name=f'bitlocker-{method:04x}.raw';(OUT/(name+'.gz')).write_bytes(gzip.compress(encrypted,mtime=0))
  records[name]={'method':method,'key':key.hex(),'vmk':vmk.hex(),'size':size,'sha256':hashlib.sha256(encrypted).hexdigest(),'decoded_sha256':hashlib.sha256(expected).hexdigest()}
  print(name,'generated')
 (OUT/'bitlocker-generated.json').write_text(json.dumps({'password':password,'recovery_password':recovery,'records':records},indent=2)+'\n')
if __name__=='__main__':main()
