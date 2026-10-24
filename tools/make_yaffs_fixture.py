"""Build a packed-tags YAFFS2 image for independent TSK validation."""
import gzip, hashlib, struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]/'tests/fixtures/layers'
def make():
    page=2048;spare=64;stride=page+spare
    data=bytearray(b'\xff'*(stride*64*4))
    def header(slot,oid,parent,name,typ,size=0,alias='',equivalent=0,seq=0x1000):
        at=slot*stride;d=bytearray(2048)
        struct.pack_into('<II',d,0,typ,parent)
        name=name.encode();d[10:10+len(name)]=name
        mode={1:0o100644,2:0o120777,3:0o40755,4:0o100644}[typ]
        struct.pack_into('<IIIIIIII',d,268,mode,1000,1000,1700000000,1700000001,1700000002,size,equivalent)
        alias=alias.encode();d[300:300+len(alias)]=alias
        data[at:at+2048]=d
        struct.pack_into('<IIII',data,at+page,seq,oid,0,0xffff)
    def chunk(slot,oid,index,payload,seq=0x1000):
        at=slot*stride;data[at:at+len(payload)]=payload
        struct.pack_into('<IIII',data,at+page,seq,oid,index,len(payload))
    header(0,1,1,'',3)
    header(1,256,1,'subdir',3)
    header(2,257,1,'fragmented.bin',1,3000)
    payload=bytes((i*11+3)%251 for i in range(3000))
    chunk(3,257,1,b'X'*2048)
    chunk(7,257,2,payload[2048:])
    chunk(8,257,1,payload[:2048])
    header(9,258,256,'child.txt',1,12)
    chunk(10,258,1,b'hello yaffs!')
    header(11,259,1,'a_link',2,alias='subdir/child.txt')
    header(12,260,1,'hardlink',4,equivalent=258)
    header(13,261,1,'empty',1)
    header(14,262,3,'deleted',1,4)
    chunk(15,262,1,b'gone')
    header(16,263,1,'sparse.bin',1,4096)
    chunk(17,263,2,b'Z'*2048)
    (ROOT/'yaffs2.raw.gz').write_bytes(gzip.compress(data,mtime=0))
    (ROOT/'YAFFS_RAW_SHA256SUMS').write_text(hashlib.sha256(data).hexdigest()+'  yaffs2.raw\n',encoding='ascii')
    print('yaffs2.raw',len(data))
if __name__=='__main__':make()
