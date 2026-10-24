"""Independent TSK file-content checks and libewf wrapping of forensic fixtures."""
import argparse,gzip,hashlib,json,subprocess
from pathlib import Path
from validate_libewf import Libewf
ROOT=Path(__file__).resolve().parents[1];FIX=ROOT/'tests/fixtures/forensics'
def main():
 p=argparse.ArgumentParser();p.add_argument('--tsk-bin',type=Path,required=True);p.add_argument('--libewf',type=Path,required=True);p.add_argument('--generate',action='store_true');args=p.parse_args();work=ROOT/'target/forensics-corpus';work.mkdir(exist_ok=True);results={}
 for name,record,expected_name in [('ntfs-forensics.raw','66','compressed-source.bin'),('ntfs-deleted.raw','27',None)]:
  data=gzip.decompress((FIX/(name+'.gz')).read_bytes());path=work/name;path.write_bytes(data)
  expected=gzip.decompress((FIX/(expected_name+'.gz')).read_bytes()) if expected_name else b'resident deleted evidence'
  result=subprocess.run([str(args.tsk_bin/'icat.exe'),'-f','ntfs','-r',str(path),record],capture_output=True,check=True);assert result.stdout==expected
  results[name]={'record':int(record),'bytes':len(expected),'sha256':hashlib.sha256(result.stdout).hexdigest()}
 library=Libewf(args.libewf)
 if args.generate:
  raw=gzip.decompress((FIX/'ntfs-journal-security.raw.gz').read_bytes());base=FIX/'ntfs-forensics'
  if not base.with_suffix('.E01').exists():library.write(base,raw,6,2)
  assert library.read([base.with_suffix('.E01')])==raw
  encrypted=gzip.decompress((FIX/'bitlocker-8004.raw.gz').read_bytes());raw=bytearray(len(encrypted)+1048576);raw[1048576:]=encrypted;raw[446+4]=7;raw[446+8:446+12]=(2048).to_bytes(4,'little');raw[446+12:446+16]=(len(encrypted)//512).to_bytes(4,'little');raw[510:512]=b'\x55\xaa';base=FIX/'bitlocker-mbr'
  if not base.with_suffix('.E01').exists():library.write(base,bytes(raw),6,2)
  assert library.read([base.with_suffix('.E01')])==raw
 (FIX/'tsk-forensic-reference.json').write_text(json.dumps(results,indent=2)+'\n');print('TSK checks and E01 byte comparisons passed')
if __name__=='__main__':main()
