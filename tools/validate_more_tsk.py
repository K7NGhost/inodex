"""Generate independent metadata and SHA256 expectations using official TSK 4.15.

python tools/validate_more_tsk.py --bin target/tsk-oracle/sleuthkit-4.15.0-win32/bin
Release ZIP SHA256: c2ebab8105b893d97bd8ce35b88e01985e2a106efc97f03adf95840a631b20ce
"""
import argparse,gzip,hashlib,json,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bin',type=Path,required=True);args=p.parse_args()
    def run(tool,options):
        return subprocess.check_output([str(args.bin/(tool+'.exe'))]+[str(a) for a in options])
    result={'version':run('fls',['-V']).decode().strip(),'filesystems':{}}
    with tempfile.TemporaryDirectory(prefix='inodex-more-') as temp:
        for name in ['apfs','apfs-internal','hfsplus','hfsx','hfs-overflow','ufs1','ufs2','ufs1-indirect','ufs2-indirect','ufs1-be','ufs2-be','iso9660','iso-joliet','iso-rockridge','iso-multi','yaffs2']:
            data=gzip.decompress((ROOT/'tests/fixtures/layers'/f'{name}.raw.gz').read_bytes())
            if name.startswith('iso'):
                offset=int.from_bytes(data[32768+156+24:32768+156+25],'little',signed=True)*900
                result.setdefault('iso_recording_offsets',{})[name]=offset
            if name in ('ufs1','ufs2'):data=data[8192:]
            image=Path(temp)/(name+'.raw');image.write_bytes(data)
            opts=['-B','107'] if name.startswith('apfs') else []
            if name=='yaffs2':
                Path(str(image)+'-yaffs2.config').write_text('flash_page_size=2048\nflash_spare_size=64\nflash_chunks_per_block=64\nspare_seq_num_offset=0\nspare_obj_id_offset=4\nspare_chunk_id_offset=8\n')
                opts=['-f','yaffs2']
            output=run('fls',['-z','UTC0','-r','-u','-m','/']+opts+[image])
            try: listing=output.decode('utf-8')
            except UnicodeDecodeError: listing=output.decode('cp1252') # official Windows build's redirected wide output
            entries=[]
            for line in listing.splitlines():
                fields=line.split('|')
                if len(fields)!=11:raise ValueError(line)
                _,path,inode,mode,uid,gid,size,atime,mtime,ctime,crtime=fields
                if path.startswith('/$'):continue
                record={'path':path.split(' -> ',1)[0],'id':int(inode.split('-')[0]),'kind':{'r':'file','d':'directory','l':'symlink'}.get(mode[0],'other'),'size':int(size),'uid':int(uid),'gid':int(gid),'accessed':int(atime),'modified':int(mtime),'changed':int(ctime),'created':int(crtime)}
                if name=='iso-rockridge':
                    # TSK exposes ISO names and types, ignoring these authored
                    # Rock Ridge names and symlink. Keep its output unchanged.
                    record['source_path']={'/DOCS':'/docs','/DOCS/NOTE.TXT':'/docs/note.txt','/LINK':'/a_link','/LONG.TXT':'/long_'+'a'*190+'.txt'}[record['path']]
                    if record['path']=='/LINK':record['source_target']='docs/note.txt'
                if record['kind']=='symlink':
                    target=path.split(' -> ',1)[1].encode() if ' -> ' in path else run('icat',opts+[image,inode])
                    record['target']=target.decode();record['logical_size']=len(target);record['sha256']=hashlib.sha256(target).hexdigest()
                elif record['kind']=='file':
                    payload=run('icat',opts+[image,inode]) if int(size) else b''
                    assert len(payload)==int(size),(name,path)
                    record['sha256']=hashlib.sha256(payload).hexdigest()
                entries.append(record)
            if name in ['apfs','hfsplus']:
                inode=23 if name=='apfs' else 25
                payload=run('icat',opts+[image,str(inode)+'-4353-1'])
                result.setdefault('resource_forks',{})[name]={'size':len(payload),'sha256':hashlib.sha256(payload).hexdigest()}
            result['filesystems'][name]=sorted(entries,key=lambda e:e['path'])
            print(name,len(entries))
    output=ROOT/'tests/fixtures/layers/tsk-more-reference.json'
    output.write_text(json.dumps(result,indent=2,sort_keys=True),encoding='utf-8')
if __name__=='__main__':main()
