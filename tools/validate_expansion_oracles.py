"""Independent L01/Apple/snapshot checks; production Rust does not load these tools.

python tools/validate_expansion_oracles.py --ewf-library PATH --tsk-bin PATH
Add --write-reference to regenerate the independently enumerated L01 JSON.
"""
from pathlib import Path
import argparse,ctypes as c,gzip,hashlib,json,subprocess,tempfile
from validate_libewf import Libewf
ROOT=Path(__file__).resolve().parents[1];FIX=ROOT/'tests/fixtures/expansion'
def logical_rows(library,paths):
    lib=Libewf(library);handle=lib.handle(paths,1);ptr=c.c_void_p;error=c.POINTER(ptr);native=lib.lib
    functions={
        'handle_get_root_file_entry':[ptr,c.POINTER(ptr),error],
        'file_entry_get_number_of_sub_file_entries':[ptr,c.POINTER(c.c_int),error],
        'file_entry_get_sub_file_entry':[ptr,c.c_int,c.POINTER(ptr),error],
        'file_entry_get_utf8_name_size':[ptr,c.POINTER(c.c_size_t),error],
        'file_entry_get_utf8_name':[ptr,ptr,c.c_size_t,error],
        'file_entry_get_size':[ptr,c.POINTER(c.c_uint64),error],
        'file_entry_read_buffer':[ptr,ptr,c.c_size_t,error],
        'file_entry_free':[c.POINTER(ptr),error],
    }
    for name,args in functions.items():
        fn=getattr(native,'libewf_'+name);fn.argtypes=args;fn.restype=c.c_ssize_t if name=='file_entry_read_buffer' else c.c_int
    def call(name,*args):
        error=ptr();n=getattr(native,'libewf_'+name)(*args,c.byref(error))
        if n<0:
            message=c.create_string_buffer(4096);native.libewf_error_backtrace_sprint(error,message,len(message));native.libewf_error_free(c.byref(error));raise RuntimeError(name+': '+message.value.decode(errors='replace'))
        return n
    result=[]
    def visit(entry,parent):
        n=c.c_size_t();call('file_entry_get_utf8_name_size',entry,c.byref(n));name=c.create_string_buffer(n.value);call('file_entry_get_utf8_name',entry,name,n.value)
        path='' if parent is None else parent+'/'+name.value.decode()
        size=c.c_uint64();call('file_entry_get_size',entry,c.byref(size));count=c.c_int();call('file_entry_get_number_of_sub_file_entries',entry,c.byref(count))
        data=c.create_string_buffer(size.value)
        if size.value:
            try:assert call('file_entry_read_buffer',entry,data,size.value)==size.value
            except Exception as e:raise RuntimeError(path+': '+str(e)) from e
        result.append({'path':path,'size':size.value,'children':count.value,'sha256':hashlib.sha256(data.raw).hexdigest()})
        for i in range(count.value):
            child=ptr();call('file_entry_get_sub_file_entry',entry,i,c.byref(child))
            try:visit(child,path)
            finally:call('file_entry_free',c.byref(child))
    root=ptr()
    try:
        call('handle_get_root_file_entry',handle,c.byref(root));visit(root,None)
    finally:
        if root:call('file_entry_free',c.byref(root))
        lib.finish(handle)
    return result
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--ewf-library',type=Path,required=True);p.add_argument('--tsk-bin',type=Path,required=True);p.add_argument('--write-reference',action='store_true');args=p.parse_args()
    rows=logical_rows(args.ewf_library,[(FIX/'tracy-phone.L01').resolve()]);assert len(rows)==9952
    if args.write_reference:(FIX/'l01-reference.json.gz').write_bytes(gzip.compress(json.dumps(rows,indent=2).encode(),mtime=0))
    else:assert rows==json.loads(gzip.decompress((FIX/'l01-reference.json.gz').read_bytes()))
    small=logical_rows(args.ewf_library,[(FIX/'logical-split.L01').resolve(),(FIX/'logical-split.L02').resolve()]);expected=json.loads((FIX/'logical-split-source.json').read_text())
    for row in small[1:]:assert {k:row[k] for k in ['size','sha256']}==expected[row['path'][1:]]
    print('libewf: 9,952 real L01 entries and 5 split-set entries match known content')
    expected=json.loads((FIX/'compression-source.json').read_text());reference=json.loads((FIX/'tsk-reference.json').read_text())
    def run(tool,options):return subprocess.check_output([str(args.tsk_bin/(tool+'.exe'))]+list(map(str,options)))
    with tempfile.TemporaryDirectory() as temp:
        for family in ['hfs','apfs']:
            for method in [3,4,7,8]:
                name=f'{family}-compressed-{method}';path=Path(temp)/(name+'.raw');path.write_bytes(gzip.decompress((FIX/(name+'.raw.gz')).read_bytes()));options=['-B','107'] if family=='apfs' else []
                decoded=run('icat',options+[path,'18' if family=='apfs' else '20']);assert hashlib.sha256(decoded).hexdigest()==expected[str(method)]['sha256']
        path=Path(temp)/'snapshot.raw';path.write_bytes(gzip.decompress((FIX/'apfs-snapshot.raw.gz').read_bytes()))
        for snap in [False,True]:
            payload=run('icat',['-B','107']+(['-S','3'] if snap else [])+[path,'18']);assert hashlib.sha256(payload).hexdigest()==reference['apfs-snapshot-'+str(snap)]['sha256']
    print('TSK: zlib/LZVN HFS/APFS files and both live/snapshot versions match')
if __name__=='__main__':main()
