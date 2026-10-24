"""Independent BitLocker To Go reference and compact public fixture selection.

Reads the pinned Windows-written dfVFS image. OpenSSL authenticates key blobs;
the documented diffuser and FAT allocation map select original encrypted ranges.
Unselected bytes are zeroed, so the result is explicitly NOT a complete image.
"""
import sys,gzip,struct as s,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'target/crypto-oracle'))
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
def entries(data):
 at=0
 while at<len(data) and any(data[at:]):
  n,k,v,_=s.unpack_from('<HHHH',data,at);assert n>=8;yield k,v,data[at+8:at+n];at+=n
def unseal(data,key):return AESCCM(key).decrypt(data[:12],data[28:]+data[12:28],None)
def main():
 path=ROOT/'tests/fixtures/forensics/bdetogo.raw.gz';original=gzip.decompress(path.read_bytes())
 assert hashlib.sha256(original).hexdigest()=='ed7982a1f9263e4e54889fea1fa74112d12fea0a0aa7cd8f84fc6f03198ae71b'
 locations=s.unpack_from('<QQQ',original,440);at=locations[0];size=s.unpack_from('<I',original,at+64)[0];metadata=original[at+112:at+64+size];items=list(entries(metadata));method=s.unpack_from('<H',original,at+100)[0];assert method==0x8000
 protector=next(p for k,v,p in items if k==2 and v==8 and s.unpack_from('<H',p,26)[0]==0x2000);props=list(entries(protector[28:]));salt=next(p[4:20] for _,v,p in props if v==3);initial=hashlib.sha256(hashlib.sha256('bde-TEST'.encode('utf-16le')).digest()).digest();last=bytes(32)
 for i in range(0x100000):last=hashlib.sha256(last+initial+salt+s.pack('<Q',i)).digest()
 vmk=unseal(next(p for _,v,p in props if v==5),last)[12:];key=unseal(next(p for k,v,p in items if k==3 and v==5),vmk)[12:];header_at,header_size=s.unpack('<QQ',next(p[:16] for k,v,p in items if k==15 and v==15))
 selected=bytearray(len(original));ranges={}
 def keep(at,length):
  selected[at:at+length]=original[at:at+length];ranges[at]=max(length,ranges.get(at,0))
 keep(0,512)
 for at in locations:keep(at,65536)
 ecb=Cipher(algorithms.AES(key[:16]),modes.ECB());tweak=Cipher(algorithms.AES(key[32:48]),modes.ECB())
 def sector(at):
  physical=header_at+at if at<header_size else at;keep(physical,512);iv=ecb.encryptor().update(physical.to_bytes(16,'little'));data=Cipher(algorithms.AES(key[:16]),modes.CBC(iv)).decryptor().update(original[physical:physical+512]);words=list(s.unpack('<128I',data))
  rol=lambda x,n:((x<<n)|(x>>(32-n if n else 32)))&0xffffffff
  for rounds,delta,rotation in [(3,1,[0,10,0,25]),(5,-1,[9,0,13,0])]:
   for _ in range(rounds):
    for i in range(128):words[i]=(words[i]+(words[(i+delta*2)%128]^rol(words[(i+delta*5)%128],rotation[i%4])))&0xffffffff
  mask=tweak.encryptor().update(physical.to_bytes(16,'little')+(physical+(0x80<<120)).to_bytes(16,'little'));return bytes(v^mask[i%32] for i,v in enumerate(s.pack('<128I',*words)))
 def read(at,length):return b''.join(sector(i) for i in range(at//512*512,(at+length+511)//512*512))[at%512:at%512+length]
 boot=read(0,512);assert boot[510:]==b'\x55\xaa';bps=s.unpack_from('<H',boot,11)[0];spc=boot[13];reserved=s.unpack_from('<H',boot,14)[0];fats=boot[16];root_entries=s.unpack_from('<H',boot,17)[0];spf=s.unpack_from('<H',boot,22)[0];assert bps==512
 fat=read(reserved*bps,spf*bps);root_at=(reserved+fats*spf)*bps;root_bytes=(root_entries*32+511)//512*512;root=read(root_at,root_bytes);data_at=root_at+root_bytes;cluster_bytes=spc*bps
 for copy in range(1,fats):read((reserved+copy*spf)*bps,spf*bps)
 total=s.unpack_from('<H',boot,19)[0] or s.unpack_from('<I',boot,32)[0];clusters=(total*bps-data_at)//cluster_bytes;assert clusters<65525
 def next_cluster(number):
  if clusters>=4085:return int.from_bytes(fat[number*2:number*2+2],'little')
  v=int.from_bytes(fat[number*3//2:number*3//2+2],'little');return (v>>4 if number&1 else v)&0xfff
 allocated=[]
 for number in range(2,clusters+2):
  value=next_cluster(number)
  if value and value!=(0xfff7 if clusters>=4085 else 0xff7):allocated.append(number)
 # Independently resolve the known short directory entry and recover its chain.
 record=next(root[i:i+32] for i in range(0,len(root),32) if root[i:i+11]==b'PASSWORDTXT') if b'PASSWORDTXT' in root else next(root[i:i+32] for i in range(0,len(root),32) if root[i:i+8].startswith(b'PASSWO'))
 cluster=s.unpack_from('<H',record,26)[0];length=s.unpack_from('<I',record,28)[0];content=bytearray();seen=set()
 while 2<=cluster<(0xfff0 if clusters>=4085 else 0xff0):
  assert cluster not in seen;seen.add(cluster);content+=read(data_at+(cluster-2)*cluster_bytes,cluster_bytes);cluster=next_cluster(cluster)
 content=content[:length];assert hashlib.sha256(content).hexdigest()=='02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252'
 output=ROOT/'tests/fixtures/forensics/bdetogo-selected.raw.gz';output.write_bytes(gzip.compress(selected,mtime=0));report={'source':'https://raw.githubusercontent.com/log2timeline/dfvfs/d365f334da42169276e2083a27f75bc2afa48ea8/test_data/bdetogo.raw','source_sha256':hashlib.sha256(original).hexdigest(),'selected_sha256':hashlib.sha256(selected).hexdigest(),'image_size':len(original),'selection':'Only original metadata, FAT/root and passwords.txt data sectors retained. Other bytes are zero, not original evidence.','physical_ranges':sorted(ranges.items()),'known_file_sha256':hashlib.sha256(content).hexdigest()};(ROOT/'tests/fixtures/forensics/bdetogo-selection.json').write_text(json.dumps(report,indent=2)+'\n')
 archive=ROOT/'target/bdetogo-original.raw.gz';path.replace(archive)
 print('Independent BitLocker/FAT reference PASS;',len(allocated),'clusters; compressed selected fixture',output.stat().st_size)
if __name__=='__main__':main()
