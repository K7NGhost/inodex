"""Create derived edge fixtures and optional independently encoded E01 wrappers.

ISO authoring requires pycdlib 1.14.0 in target/fixture-tools. Other operations
use only Python's standard library, plus optional development-only libewf.
"""
import argparse,gzip,hashlib,io,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'tests/fixtures/layers'
def read(name):return gzip.decompress((OUT/(name+'.raw.gz')).read_bytes())
def save(name,data):
    (OUT/(name+'.raw.gz')).write_bytes(gzip.compress(data,mtime=0))
    print(name,len(data),hashlib.sha256(data).hexdigest())
def hfsx():
    data=bytearray(read('hfsplus'))
    for at in [1024,len(data)-1024]:struct.pack_into('>HH',data,at,0x4858,5)
    block=struct.unpack_from('>I',data,1064)[0]
    catalog=struct.unpack_from('>I',data,1024+272+16)[0]*block
    data[catalog+51]=0xbc
    # Binary HFSX ordering differs from HFS+ ordering for ignorable NUL names.
    # This small catalog has a single leaf, so reorder that leaf by UTF-16 key.
    size=struct.unpack_from('>H',data,catalog+32)[0]
    leaf=struct.unpack_from('>I',data,catalog+24)[0]
    at=catalog+leaf*size
    count=struct.unpack_from('>H',data,at+10)[0]
    records=[]
    for i in range(count):
        start=struct.unpack_from('>H',data,at+size-(i+1)*2)[0]
        end=struct.unpack_from('>H',data,at+size-(i+2)*2)[0]
        records.append(bytes(data[at+start:at+end]))
    records.sort(key=lambda r:(struct.unpack_from('>I',r,2)[0],r[8:8+struct.unpack_from('>H',r,6)[0]*2]))
    data[at+14:at+size]=bytes(size-14);offset=14
    for i,r in enumerate(records):
        struct.pack_into('>H',data,at+size-(i+1)*2,offset)
        data[at+offset:at+offset+len(r)]=r;offset+=len(r)
    struct.pack_into('>H',data,at+size-(count+1)*2,offset)
    save('hfsx',data)
def ufs_indirect(name):
    data=bytearray(read(name)[8192:]);v2=name=='ufs2';sb=65536 if v2 else 8192
    def get(at):return struct.unpack_from('<I',data,at)[0]
    block=get(sb+48);frag=get(sb+52);ipg=get(sb+184);fpg=get(sb+188);groups=get(sb+44)
    free=[]
    for cg in range(groups):
        base=cg*fpg+(0 if v2 else get(sb+24)*(cg&~get(sb+28)))
        desc=(base+get(sb+12))*frag;offset=get(desc+96);count=get(desc+20)
        for start in range(0,min(fpg,count),block//frag):
            if all(data[desc+offset+(start+i)//8]&(1<<((start+i)%8)) for i in range(block//frag)):
                free.append((cg,desc+offset,start,cg*fpg+start))
    assert len(free)>=13
    allocated=free[:13]
    for cg,bitmap,start,physical in allocated:
        for i in range(block//frag):data[bitmap+(start+i)//8]&=~(1<<((start+i)%8))
    ino=get(sb+16)*frag+4*(256 if v2 else 128);ptr_at=112 if v2 else 40;fmt='<Q' if v2 else '<I';width=8 if v2 else 4
    size=12*block+321;struct.pack_into('<Q',data,ino+(16 if v2 else 8),size)
    for i in range(15):struct.pack_into(fmt,data,ino+ptr_at+i*width,0)
    physical_blocks=[p for _,_,_,p in allocated];next_block=iter(physical_blocks[:12])
    for logical in range(13):
        if logical==3:continue
        physical=next(next_block)
        length=min(block,size-logical*block)
        payload=bytes((logical*19+j)%251 for j in range(length))
        data[physical*frag:physical*frag+length]=payload
        if logical<12:struct.pack_into(fmt,data,ino+ptr_at+logical*width,physical)
        else:indirect_data=physical
    pointer=physical_blocks[12];data[pointer*frag:pointer*frag+block]=bytes(block)
    struct.pack_into(fmt,data,pointer*frag,indirect_data)
    struct.pack_into(fmt,data,ino+ptr_at+12*width,pointer)
    if v2:struct.pack_into('<Q',data,ino+24,13*block//512)
    else:struct.pack_into('<I',data,ino+104,13*block//512)
    save(name+'-indirect',data)
def iso_images():
    sys.path.insert(0,str(ROOT/'target/fixture-tools'));import pycdlib
    payload=b'Independent ISO authoring fixture\n'+bytes(range(256))*9
    for joliet in [False,True]:
        iso=pycdlib.PyCdlib();opts={'interchange_level':3,'rock_ridge':'1.09','vol_ident':'INODEX_TEST'}
        if joliet:opts['joliet']=3
        iso.new(**opts)
        args={'iso_path':'/DOCS','rr_name':'docs'}
        if joliet:args['joliet_path']='/Docs'
        iso.add_directory(**args)
        args={'iso_path':'/DOCS/NOTE.TXT;1','rr_name':'note.txt'}
        if joliet:args['joliet_path']='/Docs/Gräße.txt'
        iso.add_fp(io.BytesIO(payload),len(payload),**args)
        if not joliet:
            iso.add_symlink(symlink_path='/LINK.;1',rr_symlink_name='a_link',rr_path='docs/note.txt')
            longname='long_'+'a'*190+'.txt'
            iso.add_fp(io.BytesIO(b'continuation'),12,iso_path='/LONG.TXT;1',rr_name=longname)
        output=io.BytesIO();iso.write_fp(output);iso.close()
        save('iso-joliet' if joliet else 'iso-rockridge',output.getvalue())
def iso_multi():
    data=bytearray(read('iso9660'));root=struct.unpack_from('<I',data,32768+158)[0]*2048;at=root
    while data[at]:
        name=bytes(data[at+33:at+33+data[at+32]])
        if name.startswith(b'PASSWORDS.TXT'):break
        at+=data[at]
    else:raise ValueError('missing ISO file')
    length=data[at];record=bytes(data[at:at+length]);payload=bytes((i*13+7)%251 for i in range(2381))
    for i,(part,physical) in enumerate([(payload[:2048],100),(payload[2048:],101)]):
        target=at+i*length;data[target:target+length]=record
        struct.pack_into('<I',data,target+2,physical);struct.pack_into('>I',data,target+6,physical)
        struct.pack_into('<I',data,target+10,len(part));struct.pack_into('>I',data,target+14,len(part))
        data[target+25]=(data[target+25]&~128)|(128 if i==0 else 0)
        data[physical*2048:physical*2048+len(part)]=part
    save('iso-multi',data)
def hfs_overflow():
    data=bytearray(read('hfsplus'))
    def be32(at):return struct.unpack_from('>I',data,at)[0]
    block=be32(1064);bitmap=be32(1024+112+16)*block
    free=[i for i in range(be32(1068)) if not data[bitmap+i//8]&(0x80>>(i%8))][::2][:9]
    assert len(free)==9
    for logical,physical in enumerate(free):
        data[bitmap+physical//8]|=0x80>>(physical%8)
        data[physical*block:(physical+1)*block]=bytes((logical*23+j)%251 for j in range(block))
    cat=be32(1024+272+16)*block;size=struct.unpack_from('>H',data,cat+32)[0];leaf=cat+be32(cat+24)*size;count=struct.unpack_from('>H',data,leaf+10)[0]
    for i in range(count):
        at=leaf+struct.unpack_from('>H',data,leaf+size-(i+1)*2)[0];key=struct.unpack_from('>H',data,at)[0];value=at+((key+3)&~1)
        if struct.unpack_from('>H',data,value)[0]==2 and be32(value+8)==20:
            fork=value+88;struct.pack_into('>QII',data,fork,9*block,0,9)
            for j in range(8):struct.pack_into('>II',data,fork+16+j*8,free[j],1)
            break
    else:raise ValueError('missing passwords.txt')
    ext=be32(1024+192+16)*block
    struct.pack_into('>HIIII',data,ext+14,1,1,1,1,1)
    struct.pack_into('>I',data,ext+40,be32(ext+36)-2)
    map_at=struct.unpack_from('>H',data,ext+size-6)[0];data[ext+map_at]|=0xc0
    start=ext+size;data[start:start+size]=bytes(size)
    struct.pack_into('>IIbBHH',data,start,0,0,-1,1,1,0)
    struct.pack_into('>HBBII',data,start+14,10,0,0,20,8)
    struct.pack_into('>II',data,start+26,free[8],1)
    struct.pack_into('>HH',data,start+size-4,90,14)
    for at in [1024,len(data)-1024]:struct.pack_into('>I',data,at+48,be32(at+48)-9)
    save('hfs-overflow',data)
def apfs_internal():
    data=bytearray(read('apfs'))
    def checksum(at):
        a=b=0;m=0xffffffff
        for (word,) in struct.iter_unpack('<I',data[at+8:at+4096]):a=(a+word)%m;b=(b+a)%m
        lo=m-(a+b)%m;hi=m-(a+lo)%m;struct.pack_into('<Q',data,at,lo|(hi<<32))
    source=bytes(data[101*4096:102*4096]);count=struct.unpack_from('<I',source,36)[0];table=56+struct.unpack_from('<H',source,40)[0];keybase=table+struct.unpack_from('<H',source,42)[0]
    records=[]
    for i in range(count):
        ko,kl,vo,vl=struct.unpack_from('<HHHH',source,table+i*8)
        records.append((source[keybase+ko:keybase+ko+kl],source[4056-vo:4056-vo+vl]))
    def tree(block,oid,rows,root=False,level=0):
        at=block*4096;d=bytearray(4096);d[:32]=source[:32];struct.pack_into('<QQHH',d,8,oid,3,2 if root else 3,0)
        struct.pack_into('<HHIHH',d,32,(1 if root else 0)|(2 if level==0 else 0),level,len(rows),0,len(rows)*8)
        keybase=56+len(rows)*8;keyat=keybase;end=4056 if root else 4096;valueat=end
        for i,(key,value) in enumerate(rows):
            valueat-=(len(value)+7)//8*8
            d[keyat:keyat+len(key)]=key;d[valueat:valueat+len(value)]=value
            struct.pack_into('<HHHH',d,56+i*8,keyat-keybase,len(key),end-valueat,len(value));keyat+=len(key)
        assert keyat<valueat
        if root:d[-40:]=source[-40:];struct.pack_into('<Q',d,4096-8,3)
        data[at:at+4096]=d;checksum(at)
    half=len(records)//2;parts=[records[:half],records[half:]]
    for i,rows in enumerate(parts):tree(110+i,2000+i,rows)
    tree(101,1028,[(rows[0][0],struct.pack('<Q',2000+i)) for i,rows in enumerate(parts)],True,1)
    # Rebuild the small physical object-map leaf with the two child mappings.
    at=103*4096;original=bytes(data[at:at+4096]);d=bytearray(4096);d[:56]=original[:56]
    rows=[(1028,101),(2000,110),(2001,111)];struct.pack_into('<IHH',d,36,3,0,12)
    for i,(oid,physical) in enumerate(rows):
        key_at=68+i*16;value_at=4056-(i+1)*16
        struct.pack_into('<HH',d,56+i*4,i*16,(i+1)*16)
        struct.pack_into('<QQ',d,key_at,oid,3);struct.pack_into('<IIQ',d,value_at,0,4096,physical)
    d[-40:]=original[-40:];struct.pack_into('<Q',d,4096-16,3)
    data[at:at+4096]=d;checksum(at)
    save('apfs-internal',data)
def ufs_big_endian(name):
    source=read(name)[8192:];data=bytearray(source);v2=name=='ufs2';sb=65536 if v2 else 8192
    def u32(at):return struct.unpack_from('<I',source,at)[0]
    def flip(at,n):data[at:at+n]=source[at:at+n][::-1]
    frag=u32(sb+52);ipg=u32(sb+184);fpg=u32(sb+188);groups=u32(sb+44)
    for o in range(0,208,4):flip(sb+o,4)
    flip(sb+1372,4)
    if v2:
        for o in range(1008,1104,8):flip(sb+o,8)
        flip(sb+1312,4)
    dirs=set()
    for cg in range(groups):
        base=cg*fpg+(0 if v2 else u32(sb+24)*(cg&~u32(sb+28)))
        desc=(base+u32(sb+12))*frag;bitmap=desc+u32(desc+92)
        for o in range(0,168,4):
            if o==16:flip(desc+16,2);flip(desc+18,2)
            else:flip(desc+o,4)
        for index in range(ipg):
            if not source[bitmap+index//8]&(1<<(index%8)):continue
            ino=(base+u32(sb+16))*frag+index*(256 if v2 else 128)
            mode=struct.unpack_from('<H',source,ino)[0];size=struct.unpack_from('<Q',source,ino+(16 if v2 else 8))[0];start=112 if v2 else 40;width=8 if v2 else 4
            flip(ino,2);flip(ino+2,2)
            if v2:
                for o in [4,8,12]+list(range(64,96,4)):flip(ino+o,4)
                for o in range(16,64,8):flip(ino+o,8)
                flip(ino+96,8);flip(ino+104,8)
            else:
                flip(ino+8,8)
                for o in list(range(16,40,4))+list(range(100,128,4)):flip(ino+o,4)
            inline=mode&0xf000==0xa000 and size<15*width
            if not inline:
                for i in range(15):flip(ino+start+i*width,width)
            if mode&0xf000==0x4000:
                for i in range((size+u32(sb+48)-1)//u32(sb+48)):
                    assert i<12
                    ptr=struct.unpack_from('<Q' if v2 else '<I',source,ino+start+i*width)[0]
                    length=min(u32(sb+48),size-i*u32(sb+48));dirs.add((ptr*frag,length))
    for start,size in dirs:
        at=start
        while at<start+size:
            length=struct.unpack_from('<H',source,at+4)[0]
            assert length>=8
            flip(at,4);flip(at+4,2);at+=length
    save(name+'-be',data)
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--libewf',type=Path);parser.add_argument('--iso',action='store_true');parser.add_argument('--ewf-names',nargs='+',default=['apfs','hfsplus','hfsx','ufs1','ufs2','iso9660','yaffs2']);args=parser.parse_args()
    hfsx()
    hfs_overflow();apfs_internal();iso_multi()
    for n in ['ufs1','ufs2']:ufs_indirect(n);ufs_big_endian(n)
    if args.iso:iso_images()
    if args.libewf:
        from validate_libewf import Libewf
        lib=Libewf(args.libewf)
        for name in args.ewf_names:
            base=OUT/name
            if base.with_suffix('.E01').exists():raise FileExistsError(base)
            lib.write(base,read(name),6,2)
    names=['hfsx','hfs-overflow','apfs-internal','ufs1-indirect','ufs2-indirect','ufs1-be','ufs2-be','iso-joliet','iso-rockridge','iso-multi']
    (OUT/'MORE_GENERATED_SHA256SUMS').write_text(''.join(hashlib.sha256(read(n)).hexdigest()+'  '+n+'.raw\n' for n in names if (OUT/(n+'.raw.gz')).exists()),encoding='ascii')
if __name__=='__main__':main()
