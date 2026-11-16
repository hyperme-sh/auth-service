"""Reject removed source-bundle directories in every newly built image layer."""
import json
from pathlib import PurePosixPath
import sys
import tarfile

with tarfile.open(sys.argv[1]) as image:
    manifests = json.load(image.extractfile('manifest.json'))
    if len(manifests) != 1:
        raise ValueError('Expected one qualified image')
    layers = manifests[0]['Layers']
    for name in layers:
        with tarfile.open(fileobj=image.extractfile(name)) as layer:
            for member in layer:
                parts = PurePosixPath(member.name).parts
                if parts[:3] == ('usr', 'share', 'doc') and len(parts) >= 5:
                    if parts[4] in ('sources', 'debian-sources', 'base-sources'):
                        raise ValueError('Source bundle remains in image layer: ' + member.name)
print('No source bundles in any of the %d image layers' % len(layers))
