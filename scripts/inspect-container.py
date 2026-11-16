"""Inspect every retained layer without executing it."""
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile

def unpack_image(archive, destination, *, enforce_user=True):
    destination.mkdir(parents=True, exist_ok=True)
    # Inspect every final-image layer, including deleted lower-layer files.
    with tarfile.open(archive) as outer:
        manifest=json.load(outer.extractfile('manifest.json'))
        if len(manifest)!=1:raise ValueError('Expected one saved image')
        config=json.load(outer.extractfile(manifest[0]['Config']))
        if enforce_user and config.get('config',{}).get('User')!='65532:65532':raise ValueError('Runtime must be unprivileged')
        configured_names = []
        for variable in config.get('config', {}).get('Env', []):
            key = variable.partition('=')[0]
            if key.startswith(('HYPERMESH_', 'CONDUCTOR_')):
                configured_names.append(key)
                if enforce_user:
                    raise ValueError('Image must not inherit routing or credential configuration')
        for i,name in enumerate(manifest[0]['Layers']):
            target=destination/str(i);target.mkdir(parents=True)
            with tarfile.open(fileobj=outer.extractfile(name)) as layer:
                members=[]
                for member in layer:
                    path=PurePosixPath(member.name)
                    if path.is_absolute() or '..' in path.parts:raise ValueError('Unsafe layer path')
                    # No links/devices are materialized; scan regular bytes in every layer.
                    if member.isfile() or member.isdir():members.append(member)
                layer.extractall(target,members=members,filter='data')
        (destination/"image-config.json").write_text(json.dumps(config,indent=2))
        return {"layers":len(manifest[0]["Layers"]),"user":config.get("config",{}).get("User", ""), "configured_environment_names": sorted(set(configured_names))}



if __name__ == '__main__':
    print(json.dumps(unpack_image(sys.argv[1], Path(sys.argv[2]))))
