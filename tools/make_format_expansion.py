"""Build specification-authored edge fixtures; validate with TSK/libewf separately.

Uses public base images already in tests/fixtures/layers and the independently
compiled Apple codec in target/format-expansion/apple-lzfse.dll. No native code
is linked into the Rust implementation or used by ordinary Rust tests.
"""
from pathlib import Path
import ctypes as c,gzip,hashlib,json,struct,subprocess,zlib
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'tests/fixtures/expansion'; WORK=ROOT/'target/format-expansion'
OUT.mkdir(exist_ok=True)
def raw(name):return bytearray(gzip.decompress((ROOT/'tests/fixtures/layers'/f'{name}.raw.gz').read_bytes()))
def save(name,data):
    (OUT/(name+'.raw.gz')).write_bytes(gzip.compress(data,mtime=0));(WORK/(name+'.raw')).write_bytes(data)
def u32(d,at,e='<'):return struct.unpack_from(e+'I',d,at)[0]
def u64(d,at,e='<'):return struct.unpack_from(e+'Q',d,at)[0]
def apfs_crc(d,block):
    at=block*4096;a=b=0;m=0xffffffff
    for (v,) in struct.iter_unpack('<I',d[at+8:at+4096]):a=(a+v)%m;b=(b+a)%m
    x=m-(a+b)%m;y=m-(a+x)%m;struct.pack_into('<Q',d,at,x|(y<<32))
def apfs_rows(d,block=101,fixed=False):
    s=d[block*4096:(block+1)*4096];count=u32(s,36);table=56+struct.unpack_from('<H',s,40)[0];length=struct.unpack_from('<H',s,42)[0];base=table+length;end=4056
    out=[]
    for i in range(count):
        if fixed:ko,vo=struct.unpack_from('<HH',s,table+i*4);kl=vl=16
        else:ko,kl,vo,vl=struct.unpack_from('<HHHH',s,table+i*8)
        out.append((bytes(s[base+ko:base+ko+kl]),bytes(s[end-vo:end-vo+vl])))
    return out
def apfs_tree(d,block,oid,rows,xid=4,subtype=14,fixed=False):
    rows=sorted(rows,key=lambda r:(u64(r[0],0) if fixed else u64(r[0],0)&0x0fffffffffffffff,0 if fixed else u64(r[0],0)>>60,r[0][8:]));s=bytearray(4096)
    struct.pack_into('<QQII',s,8,oid,xid,0x40000002 if fixed or subtype==16 else 2,subtype)
    width=4 if fixed else 8;struct.pack_into('<HHIHH',s,32,7 if fixed else 3,0,len(rows),0,len(rows)*width)
    base=56+len(rows)*width;keyat=base;end=4056;valueat=end
    for i,(key,val) in enumerate(rows):
        valueat-=(len(val)+7)//8*8
        assert keyat+len(key)<valueat
        s[keyat:keyat+len(key)]=key;s[valueat:valueat+len(val)]=val
        if fixed:struct.pack_into('<HH',s,56+i*4,keyat-base,end-valueat)
        else:struct.pack_into('<HHHH',s,56+i*8,keyat-base,len(key),end-valueat,len(val))
        keyat+=len(key)
    struct.pack_into('<IIIIIIQQ',s,4056,0,4096,16 if fixed else 0,16 if fixed else 0,0,0,len(rows),1)
    d[block*4096:(block+1)*4096]=s;apfs_crc(d,block)
def solaris(name,big=False):
    d=raw('ufs1-be' if big else 'ufs1');d=d if big else d[8192:];e='>' if big else '<';sb=8192
    get=lambda at:u32(d,at,e);frag=get(sb+52);ipg=get(sb+184);fpg=get(sb+188);dirs=[]
    struct.pack_into(e+'IIII',d,sb+1320,0,0,0,0)
    struct.pack_into(e+'I',d,sb+1356,1)
    struct.pack_into(e+'I',d,sb+(1336 if big else 132),(0x7c269d38-get(sb+32))&0xffffffff)
    for cg in range(get(sb+44)):
        base=cg*fpg+get(sb+24)*(cg&~get(sb+28));desc=(base+get(sb+12))*frag;bitmap=desc+get(desc+92)
        for idx in range(ipg):
            if not d[bitmap+idx//8]&(1<<(idx%8)):continue
            ino=(base+get(sb+16))*frag+idx*128;mode=struct.unpack_from(e+'H',d,ino)[0];size=u64(d,ino+8,e)
            struct.pack_into(e+'III',d,ino+112,0,100000+cg*ipg+idx,200000+cg*ipg+idx)
            for at in [20,28,36]:struct.pack_into(e+'I',d,ino+at,123456)
            if mode&0xf000==0x4000:
                for i in range((size+get(sb+48)-1)//get(sb+48)):
                    assert i<12;dirs.append((get(ino+40+i*4)*frag,min(get(sb+48),size-i*get(sb+48))))
    for start,size in dirs:
        at=start
        while at<start+size:
            reclen=struct.unpack_from(e+'H',d,at+4)[0];length=d[at+7];struct.pack_into(e+'H',d,at+6,length);at+=reclen
    save(name,d)
def wrapper(name,source):
    inner=raw(source);base=8192;d=bytearray(base+len(inner)+8192);d[base:base+len(inner)]=inner
    struct.pack_into('>H',d,1024,0x4244);struct.pack_into('>H',d,1042,(len(d)-4096)//512)
    struct.pack_into('>I',d,1044,512);struct.pack_into('>H',d,1052,4)
    d[1148:1150]=inner[1024:1026];struct.pack_into('>HH',d,1150,(base-2048)//512,len(inner)//512)
    save(name,d)
def snapshot():
    d=raw('apfs');rows=apfs_rows(d);payload=b'Live file changed after snapshot.\n'.ljust(116,b'!')
    changed=[]
    for k,v in rows:
        if u64(k,0)==(8<<60)|18:v=struct.pack('<QQQ',4096,143,0)
        changed.append((k,v))
    d[143*4096:143*4096+116]=payload
    apfs_tree(d,141,1028,changed)
    entries=[(struct.pack('<QQ',1028,x),struct.pack('<IIQ',0,4096,p)) for x,p in [(3,101),(4,141)]]
    apfs_tree(d,103,103,entries,subtype=11,fixed=True)
    name=b'before-edit\0';meta=struct.pack('<QQQQQIIH',89,104,1600000000000000000,1600000000000000000,0,0x40000002,0,len(name))+name
    apfs_tree(d,140,140,[(struct.pack('<Q',(1<<60)|3),meta),(struct.pack('<QH',11<<60,len(name))+name,struct.pack('<Q',3))],subtype=16)
    struct.pack_into('<Q',d,107*4096+152,140);struct.pack_into('<Q',d,107*4096+216,1);apfs_crc(d,107)
    save('apfs-snapshot',d);return payload
def codec(method,data,stored=False):
    if stored:return bytes([{3:255,4:255,7:6,8:6,9:204,10:204,11:255,12:255}[method]])+data
    if method in [3,4]:
        import zlib
        return zlib.compress(data)
    if method in [9,10]:return b'\xcc'+data
    if method in [7,8]:
        f=LIB.lzvn_encode_scratch_size;f.restype=c.c_size_t;scratch=c.create_string_buffer(f());fn=LIB.lzvn_encode_buffer
    else:
        f=LIB.lzfse_encode_scratch_size;f.restype=c.c_size_t;scratch=c.create_string_buffer(f());fn=LIB.lzfse_encode_buffer
    fn.argtypes=[c.c_void_p,c.c_size_t,c.c_void_p,c.c_size_t,c.c_void_p];fn.restype=c.c_size_t
    out=c.create_string_buffer(len(data)*2+4096);n=fn(out,len(out),c.c_char_p(data),len(data),scratch);assert n>0
    return out.raw[:n]
def compressed(method,data):
    h=b'fpmc'+struct.pack('<IQ',method,len(data))
    if method%2:return h+codec(method,data),b''
    chunks=[codec(method,data[i:i+65536],stored=i==65536) for i in range(0,len(data),65536)]
    if method==4:
        r=bytearray(260+4+len(chunks)*8);struct.pack_into('>I',r,0,256);struct.pack_into('<I',r,260,len(chunks))
        for i,chunk in enumerate(chunks):struct.pack_into('<II',r,264+i*8,len(r)-260,len(chunk));r+=chunk
        struct.pack_into('>I',r,256,len(r)-260)
    else:
        r=bytearray((len(chunks)+1)*4)
        for i,chunk in enumerate(chunks):struct.pack_into('<I',r,i*4,len(r));r+=chunk
        struct.pack_into('<I',r,len(chunks)*4,len(r))
    return h,bytes(r)
def hfs_compressed(method,payload):
    d=raw('hfsplus');block=u32(d,1064,'>');catalog=u32(d,1312,'>')*block;nodesize=struct.unpack_from('>H',d,catalog+32)[0];leaf=catalog+nodesize
    count=struct.unpack_from('>H',d,leaf+10)[0];target=None
    for i in range(count):
        start=struct.unpack_from('>H',d,leaf+nodesize-2*(i+1))[0];keylen=struct.unpack_from('>H',d,leaf+start)[0];value=leaf+start+keylen+2
        if struct.unpack_from('>H',d,value)[0]==2 and u32(d,value+8,'>')==20:target=value;break
    assert target is not None
    attr,resource=compressed(method,payload);d[target+41]|=32;d[target+88:target+168]=bytes(80)
    bitmap=u32(d,1152,'>')*block;total=u32(d,1068,'>')
    def allocate(content):
        n=(len(content)+block-1)//block
        for b in range(total-n):
            if all(not d[bitmap+x//8]&(128>>(x%8)) for x in range(b,b+n)):
                for x in range(b,b+n):d[bitmap+x//8]|=128>>(x%8)
                d[b*block:b*block+len(content)]=content
                desc=bytearray(80);struct.pack_into('>QII',desc,0,len(content),0,n);struct.pack_into('>II',desc,16,b,n);return desc
        raise ValueError('no free HFS blocks')
    if resource:d[target+168:target+248]=allocate(resource)
    else:d[target+168:target+248]=bytes(80)
    name='com.apple.decmpfs'.encode('utf-16-be');key=struct.pack('>HHIIH',12+len(name),0,20,0,len(name)//2)+name
    record=key+struct.pack('>IIII',0x10,0,0,len(attr))+attr
    if len(record)%2:record+=b'\0'
    header=bytearray(d[catalog:catalog+nodesize]);struct.pack_into('>HIIII',header,14,1,1,1,1,1);struct.pack_into('>II',header,36,2,0)
    leafnode=bytearray(nodesize);struct.pack_into('>IIBBHH',leafnode,0,0,0,255,1,1,0);leafnode[14:14+len(record)]=record
    struct.pack_into('>HH',leafnode,nodesize-4,14+len(record),14)
    d[1376:1456]=allocate(header+leafnode)
    save(f'hfs-compressed-{method}',d)
def apfs_compressed(method,payload):
    d=raw('apfs');rows=apfs_rows(d);attr,resource=compressed(method,payload);out=[]
    for k,v in rows:
        if u64(k,0)==(3<<60)|18:
            v=bytearray(v);struct.pack_into('<I',v,68,u32(v,68)|32)
        if u64(k,0)==(8<<60)|18:continue
        out.append((k,bytes(v)))
    name=b'com.apple.decmpfs\0'
    if len(attr)>512:
        d[150*4096:150*4096+len(attr)]=attr
        value=struct.pack('<HHQQQQQQ',1,48,9001,len(attr),(len(attr)+4095)//4096*4096,0,0,0)
        out.append((struct.pack('<QQ',(8<<60)|9001,0),struct.pack('<QQQ',(len(attr)+4095)//4096*4096,150,0)))
    else:value=struct.pack('<HH',2,len(attr))+attr
    out.append((struct.pack('<QH',(4<<60)|18,len(name))+name,value))
    if resource:
        name=b'com.apple.ResourceFork\0';stream=9000
        out.append((struct.pack('<QH',(4<<60)|18,len(name))+name,struct.pack('<HHQQQQQQ',1,48,stream,len(resource),(len(resource)+4095)//4096*4096,0,0,0)))
        out.append((struct.pack('<QQ',(8<<60)|stream,0),struct.pack('<QQQ',(len(resource)+4095)//4096*4096,160,0)))
        d[160*4096:160*4096+len(resource)]=resource
    apfs_tree(d,101,1028,out,xid=3);save(f'apfs-compressed-{method}',d)
def main():
    global LIB
    import argparse
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--ewf-library',type=Path);args=parser.parse_args()
    LIB=c.CDLL(str(WORK/'apple-lzfse.dll'))
    solaris('ufs1b');solaris('ufs1b-be',True);wrapper('hfs-wrapped','hfsplus');wrapper('hfsx-wrapped','hfsx');snapshot()
    expected={}
    for method in [3,4,7,8,9,10,11,12]:
        payload=(b'Apple compression independent payload\n'*40 if method%2 else b'A'*65536+bytes(i%251 for i in range(65536))+b'last partial block\n'*27)
        hfs_compressed(method,payload);apfs_compressed(method,payload)
        expected[str(method)]={'size':len(payload),'sha256':hashlib.sha256(payload).hexdigest()}
    (OUT/'compression-source.json').write_text(json.dumps(expected,indent=2))
    logical_segments(False);logical_segments(True)
    if args.ewf_library:
        from validate_libewf import Libewf
        lib=Libewf(args.ewf_library)
        for path in sorted(OUT.glob('*.raw.gz')):
            if '-decoded.' in path.name:continue
            name=path.name[:-7];data=gzip.decompress(path.read_bytes());base=OUT/name
            image=OUT/(name+'.E01')
            if not image.exists():lib.write(base,data,6,2)
            assert lib.read([image])==data,(name,'existing E01 does not match regenerated raw source')
    print('Created UFS1b, HFS wrappers, APFS snapshot and compression fixtures')
def logical_segments(multi):
    media=bytes((i*31+7)%251 for i in range(66048))
    fields=['p','n','id','opr','cr','ac','wr','mo','ha','ls','du','be']
    def entry(name,size,be,flags='',du='',directory=False,payload=b''):
        return '\t'.join(['1' if directory else '',name,'',flags,'1600000000','1600000001','1600000002','1600000003',hashlib.md5(payload).hexdigest(),str(size),du,be])
    payload=media[:20000]+media[32768:62768] if multi else media[:50000]
    rows=[('0\t4',entry('LogicalEntries',0,'0',directory=True)),('0\t0',entry('multi.bin',50000,'2 0 4e20 8000 7530' if multi else '1 0 c350',payload=payload)),('0\t0',entry('fill.bin',1000,'1 fde8 1',flags=str(0x4000000),payload=media[65000:65001]*1000)),('0\t0',entry('duplicate.bin',50000,'1 0 1',flags=str(0x4000000),du='1',payload=media[1:50001])),('0\t0',entry('empty.txt',0,'1 101d0 1'))]
    text='2\nrec\ntb\tcl\tn\n66048\t1\t1\n\nentry\n4\t1\n'+'\t'.join(fields)+'\n'+''.join(a+'\n'+b+'\n' for a,b in rows)+'\n'
    tree=text.encode('utf-16-le');head=bytearray(48);head[:16]=hashlib.md5(tree).digest();struct.pack_into('<Q',head,16,len(tree));struct.pack_into('<I',head,24,zlib.adler32(head))
    geometry=bytearray(1052);geometry[0]=14;struct.pack_into('<IIIQ',geometry,4,3,64,512,len(media)//512);geometry[36]=1;geometry[64:80]=bytes(range(16));struct.pack_into('<I',geometry,1048,zlib.adler32(geometry[:1048]))
    for seg,indices in [(1,[0]),(2,[1,2])]:
        data=bytearray(b'LVF\x09\x0d\x0a\xff\x00\x01'+struct.pack('<H',seg)+b'\0\0')
        def section(kind,payload=b'',terminal=False):
            offset=len(data);desc=bytearray(76);desc[:len(kind)]=kind.encode();struct.pack_into('<QQ',desc,16,offset if terminal else offset+76+len(payload),0 if terminal else 76+len(payload));struct.pack_into('<I',desc,72,zlib.adler32(desc[:72]));data.extend(desc);data.extend(payload)
        section('volume',geometry)
        chunks=[];offsets=[];at=len(data)+76
        for i in indices:
            block=media[i*32768:(i+1)*32768]
            encoded=zlib.compress(block) if i!=0 else block+struct.pack('<I',zlib.adler32(block));offsets.append(at|(0x80000000 if i!=0 else 0));chunks.append(encoded);at+=len(encoded)
        section('sectors',b''.join(chunks));header=bytearray(24);struct.pack_into('<I',header,0,len(indices));struct.pack_into('<I',header,20,zlib.adler32(header[:20]));offsets=b''.join(struct.pack('<I',n) for n in offsets);table=header+offsets+struct.pack('<I',zlib.adler32(offsets));section('table',table);section('table2',table)
        if seg==2:
            section('ltree',head+tree);digest=bytearray(36);digest[:16]=hashlib.md5(media).digest();struct.pack_into('<I',digest,32,zlib.adler32(digest[:32]));section('hash',digest)
        prefix='logical-multi' if multi else 'logical-split'
        section('next' if seg==1 else 'done',terminal=True);(OUT/f'{prefix}.L{seg:02}').write_bytes(data)
    expected={'multi.bin':payload,'fill.bin':media[65000:65001]*1000,'duplicate.bin':media[1:50001],'empty.txt':b''}
    (OUT/(prefix+'-source.json')).write_text(json.dumps({name:{'size':len(b),'sha256':hashlib.sha256(b).hexdigest()} for name,b in expected.items()},indent=2))
if __name__=='__main__':main()
