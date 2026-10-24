"""Windows native compression/SDDL oracles and specified NTFS forensic fixtures.

Production parsing remains Rust. Native RtlCompressBuffer/RtlDecompressBuffer
and ConvertStringSecurityDescriptorToSecurityDescriptorW provide independent
compression and ACL expectations.
"""
import ctypes as c
import gzip
import hashlib
import json
from pathlib import Path
import random
import struct as s

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'tests/fixtures/forensics'
def u16(d,o):return s.unpack_from('<H',d,o)[0]
def u32(d,o):return s.unpack_from('<I',d,o)[0]
def u64(d,o):return s.unpack_from('<Q',d,o)[0]
def p16(d,o,v):s.pack_into('<H',d,o,v)
def p32(d,o,v):s.pack_into('<I',d,o,v)
def p64(d,o,v):s.pack_into('<Q',d,o,v)
def write(name,data):
    (OUT/(name+'.gz')).write_bytes(gzip.compress(data,mtime=0))
    return {'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
def attrs(record):
    at=u16(record,20);result=[]
    while u32(record,at)!=0xffffffff:
        n=u32(record,at+4);assert n>=24;result.append(bytearray(record[at:at+n]));at+=n
    return result
def unfix(record):
    at=u16(record,4)
    for i in range(1,u16(record,6)):record[i*512-2:i*512]=record[at+i*2:at+i*2+2]
    return record
def repack(record,attributes):
    at=u16(record,20);record[at:]=bytes(len(record)-at)
    for a in attributes:record[at:at+len(a)]=a;at+=len(a)
    assert at+8<=1024
    p32(record,at,0xffffffff);p32(record,24,at+8)
    usa=u16(record,4);record[usa:usa+2]=b'\xa5\x5a'
    for i in range(1,3):record[usa+i*2:usa+i*2+2]=record[i*512-2:i*512];record[i*512-2:i*512]=record[usa:usa+2]
    return record
def resident(kind,data,name='',instance=0):
    name=name.encode('utf-16le');start=(24+len(name)+7)//8*8;n=(start+len(data)+7)//8*8;a=bytearray(n)
    p32(a,0,kind);p32(a,4,n);a[9]=len(name)//2;p16(a,10,24);p16(a,14,instance);p32(a,16,len(data));p16(a,20,start);a[24:24+len(name)]=name;a[start:start+len(data)]=data
    return a
def nonresident(kind,runs,size,name='',flags=0,unit=0,initialized=None):
    name=name.encode('utf-16le');start=(72+len(name)+7)//8*8;mapping=bytearray();previous=0;clusters=0
    for lcn,count in runs:
        clusters+=count
        if lcn is None:mapping+=bytes([1,count])
        else:mapping+=b'\x21'+bytes([count])+s.pack('<h',lcn-previous);previous=lcn
    mapping+=b'\0';n=(start+len(mapping)+7)//8*8;a=bytearray(n);p32(a,0,kind);p32(a,4,n);a[8]=1;a[9]=len(name)//2;p16(a,10,72);p16(a,12,flags);p64(a,24,clusters-1);p16(a,32,start);p16(a,34,unit);p64(a,40,sum(count for lcn,count in runs if lcn is not None)*4096);p64(a,48,size);p64(a,56,size if initialized is None else initialized);a[72:72+len(name)]=name;a[start:start+len(mapping)]=mapping
    if flags&0x8001:
        p64(a,64,sum(count for lcn,count in runs if lcn is not None)*4096);p64(a,40,clusters*4096)
    return a
def windows_compress(data):
    lib=c.WinDLL('ntdll');workspace=c.c_uint32();fragment=c.c_uint32()
    assert lib.RtlGetCompressionWorkSpaceSize(2,c.byref(workspace),c.byref(fragment))==0
    work=c.create_string_buffer(workspace.value);output=c.create_string_buffer(len(data)*2+4096);length=c.c_uint32()
    status=lib.RtlCompressBuffer(2,data,len(data),output,len(output),4096,c.byref(length),work)
    assert status>=0,hex(status&0xffffffff)
    packed=output.raw[:length.value];plain=c.create_string_buffer(len(data));decoded=c.c_uint32()
    assert lib.RtlDecompressBuffer(2,plain,len(data),packed,len(packed),c.byref(decoded))==0
    assert decoded.value==len(data) and plain.raw==data
    return packed
def windows_security(text):
    lib=c.WinDLL('advapi32');ptr=c.c_void_p();size=c.c_uint32()
    assert lib.ConvertStringSecurityDescriptorToSecurityDescriptorW(c.c_wchar_p(text),1,c.byref(ptr),c.byref(size))
    try:return c.string_at(ptr,size.value)
    finally:
        kernel=c.WinDLL('kernel32');kernel.LocalFree.argtypes=[c.c_void_p];kernel.LocalFree(ptr)
def main():
    OUT.mkdir(exist_ok=True);records={}
    raw=bytearray(gzip.decompress((ROOT/'tests/fixtures/layers/ntfs.raw.gz').read_bytes()));mft=u64(raw,48)*4096
    bitmap_record=unfix(bytearray(raw[mft+6*1024:mft+7*1024]));bitmap_attr=next(a for a in attrs(bitmap_record) if u32(a,0)==0x80)
    mapping_at=u16(bitmap_attr,32);width=bitmap_attr[mapping_at]>>4;count_width=bitmap_attr[mapping_at]&15
    bitmap_lcn=int.from_bytes(bitmap_attr[mapping_at+1+count_width:mapping_at+1+count_width+width],'little',signed=True)
    live_clusters=[800,820,*range(832,848),864]
    for cluster in [*live_clusters,880,928]:assert not raw[bitmap_lcn*4096+cluster//8]&(1<<(cluster%8)),f'fixture cluster {cluster} overlaps source allocation'
    source=b'A'*65536+random.Random(143).randbytes(65536)+bytes(65536)+b'tail forensic data'
    packed=windows_compress(source[:65536]);records['windows.lznt1']=write('windows.lznt1',packed);records['compressed-source.bin']=write('compressed-source.bin',source)
    variable=(bytes(range(256))*17+b'abcdefgh'*29+b'forensic-pattern'*100)*5
    records['windows-variable.lznt1']=write('windows-variable.lznt1',windows_compress(variable));records['windows-variable.bin']=write('windows-variable.bin',variable)
    sd=windows_security('O:SYG:BAD:PAI(D;;WD;;;BG)(A;;FA;;;SY)(A;;FR;;;BU)S:(AU;SA;FR;;;WD)')
    records['windows.sd']=write('windows.sd',sd)
    base=unfix(bytearray(raw[mft+66*1024:mft+67*1024]));original=attrs(base)
    mapping=[(800,1),(820,1),(None,14),(832,16),(None,16),(864,1),(None,15)]
    # Split compressed bytes across two physical clusters to exercise fragmented units.
    # Native compressed output is small; split the physical prefix within a unit
    # by storing it in two allocated clusters before the sparse tail.
    assert len(packed)<8192
    raw[800*4096:801*4096]=packed[:4096].ljust(4096,b'\0');raw[820*4096:821*4096]=packed[4096:].ljust(4096,b'\0')
    raw[832*4096:848*4096]=source[65536:131072];raw[864*4096:865*4096]=source[196608:].ljust(4096,b'\0')
    # Last short unit is stored as a plain LZNT1 chunk (native compressor too).
    tail=windows_compress(source[196608:]);raw[864*4096:865*4096]=tail.ljust(4096,b'\0')
    for cluster in live_clusters:raw[bitmap_lcn*4096+cluster//8]|=1<<(cluster%8)
    replace=[]
    for a in original:
        kind=u32(a,0)
        replace.append(nonresident(0x80,mapping,len(source),flags=1,unit=4) if kind==0x80 else resident(0x50,sd) if kind==0x50 else a)
    raw[mft+66*1024:mft+67*1024]=repack(base,replace)
    records['ntfs-forensics.raw']=write('ntfs-forensics.raw',raw)
    # Deleted resident and nonresident records are independent of the live tree.
    for record_id,runs in [(27,None),(28,[(880,1)]),(29,[(832,1)])]:
        record=unfix(bytearray(raw[mft+65*1024:mft+66*1024]));p16(record,22,0);p32(record,44,record_id)
        a=[]
        for attr in attrs(record):
            kind=u32(attr,0)
            if kind==0x80:a.append(resident(0x80,b'resident deleted evidence') if runs is None else nonresident(0x80,runs,4096))
            else:a.append(attr)
        raw[mft+record_id*1024:mft+(record_id+1)*1024]=repack(record,a)
    raw[880*4096:881*4096]=b'deleted cluster evidence'.ljust(4096,b'\0')
    # Cluster 832 belongs to the live compressed file; cluster 880 remains free.
    records['ntfs-deleted.raw']=write('ntfs-deleted.raw',raw)
    # Shared $Secure:$SDS descriptor path, instead of per-file legacy 0x50.
    secure=unfix(bytearray(raw[mft+9*1024:mft+10*1024]));secure_attrs=[a for a in attrs(secure) if u32(a,0) in [0x10,0x30]]
    checksum=0
    for at in range(0,len(sd),4):checksum=(((checksum<<3)|(checksum>>29))+int.from_bytes(sd[at:at+4].ljust(4,b'\0'),'little'))&0xffffffff
    sds=s.pack('<IIQI',checksum,256,0,len(sd)+20)+sd
    secure_attrs.append(resident(0x80,sds,'$SDS'));raw[mft+9*1024:mft+10*1024]=repack(secure,secure_attrs)
    record=unfix(bytearray(raw[mft+66*1024:mft+67*1024]));attributes=[]
    for a in attrs(record):
        if u32(a,0)==0x50:continue
        if u32(a,0)==0x10:
            si=bytearray(a[u16(a,20):u16(a,20)+u32(a,16)]).ljust(72,b'\0');p32(si,52,256);a=resident(0x10,si)
        attributes.append(a)
    raw[mft+66*1024:mft+67*1024]=repack(record,attributes)
    # USN v2 records in a sparse $J stream. The logical hole must be skipped.
    journal=bytearray(4096);pos=0
    for number,name in enumerate(['created.txt','renamed-日本語.txt','deleted.txt']):
        name=name.encode('utf-16le');length=(60+len(name)+7)//8*8;entry=bytearray(length);p32(entry,0,length);p16(entry,4,2);p64(entry,8,66|(1<<48));p64(entry,16,5|(5<<48));p64(entry,24,4096+pos);p64(entry,32,132000000000000000+number);p32(entry,40,[0x100,0x2000,0x200][number]);p32(entry,48,256);p16(entry,56,len(name));p16(entry,58,60);entry[60:60+len(name)]=name;journal[pos:pos+length]=entry;pos+=length
    raw[928*4096:929*4096]=journal;raw[bitmap_lcn*4096+928//8]|=1<<(928%8)
    record=unfix(bytearray(raw[mft+26*1024:mft+27*1024]));p16(record,22,1);attributes=[a for a in attrs(record) if u32(a,0) in [0x10,0x30]]
    attributes.append(nonresident(0x80,[(None,1),(928,1)],8192,'$J',flags=0x8000));attributes.append(resident(0x80,s.pack('<QQQQ',8192,4096,123456789,4096),'$Max'))
    raw[mft+26*1024:mft+27*1024]=repack(record,attributes)
    old='$Reparse'.encode('utf-16le');new='$UsnJrnl'.encode('utf-16le')
    for index in [11,26]:
        record=unfix(bytearray(raw[mft+index*1024:mft+(index+1)*1024]));a=attrs(record)
        for attr in a:
            if old in attr:attr[:]=attr.replace(old,new)
        raw[mft+index*1024:mft+(index+1)*1024]=repack(record,a)
    # Two independently specified LFS restart pages in $LogFile's existing run.
    record=unfix(bytearray(raw[mft+2*1024:mft+3*1024]));a=next(a for a in attrs(record) if u32(a,0)==0x80);mapping_at=u16(a,32);width=a[mapping_at]>>4;count_bytes=a[mapping_at]&15;log_lcn=int.from_bytes(a[mapping_at+1+count_bytes:mapping_at+1+count_bytes+width],'little',signed=True)
    for page_number in [0,1]:
        page=bytearray(4096);page[:4]=b'RSTR';p16(page,4,32);p16(page,6,9);p32(page,16,4096);p32(page,20,4096);p16(page,24,64);p16(page,26,1);p16(page,28,1);p64(page,64,0x123456789+page_number);p16(page,72,0);p16(page,78,2);p32(page,80,43);p16(page,84,48);p16(page,86,48);p64(page,88,u64(a,48));p16(page,100,48);p16(page,102,64)
        page[32:34]=b'\xa5\x5a'
        for i in range(1,9):page[32+i*2:34+i*2]=page[i*512-2:i*512];page[i*512-2:i*512]=page[32:34]
        at=log_lcn*4096+page_number*4096;raw[at:at+4096]=page
    records['ntfs-journal-security.raw']=write('ntfs-journal-security.raw',raw)
    (OUT/'sources.json').write_text(json.dumps({'writer':'Windows native APIs plus specified NTFS record modifications','sddl':'O:SYG:BAD:PAI(D;;WD;;;BG)(A;;FA;;;SY)(A;;FR;;;BU)S:(AU;SA;FR;;;WD)','files':records},indent=2)+'\n')
    print('Generated',len(records),'independently checked forensic fixture components')
if __name__=='__main__':main()
