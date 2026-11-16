import importlib.util
import json
from pathlib import Path
import sys
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import inventory_registry as registry



def test_registry_pagination_cannot_escape():
    for url in ['https://evil.invalid/v2/hyperme-sh/auth-service/runtime/tags/list','https://ghcr.io/v2/other/runtime/tags/list','https://ghcr.io/v2/hyperme-sh/auth-service/runtime/../other']:
        with pytest.raises(ValueError):registry.registry_url(url)


def test_authorized_empty_inventory_is_distinct_from_request_failure():
    result=registry.inventory(lambda url:({'tags':[]},{},b''))
    assert result['images']==[]
    def denied(url):raise PermissionError('denied')
    with pytest.raises(PermissionError):registry.inventory(denied)


def test_registry_manifest_digest_must_match():
    def request(url):
        if '/tags/' in url:return {'tags':['test']},{},b''
        return {},{'Docker-Content-Digest':'sha256:'+'a'*64},b'{}'
    with pytest.raises(ValueError,match='manifest bytes'):registry.inventory(request)


def test_old_layer_inspection_rejects_traversal_and_observes_root_user(tmp_path):
    import io
    import tarfile
    spec=importlib.util.spec_from_file_location('inspect_old',ROOT/'scripts/inspect-container.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    def image(path,member):
        layer=io.BytesIO()
        with tarfile.open(fileobj=layer,mode='w') as t:
            item=tarfile.TarInfo(member);item.size=4;t.addfile(item,io.BytesIO(b'data'))
        with tarfile.open(path,'w') as t:
            for name,data in [('manifest.json',json.dumps([{'Config':'config.json','Layers':['layer.tar']}]).encode()),('config.json',b'{"config":{"User":"0"}}'),('layer.tar',layer.getvalue())]:
                item=tarfile.TarInfo(name);item.size=len(data);t.addfile(item,io.BytesIO(data))
    archive=tmp_path/'image.tar';image(archive,'safe.txt')
    result=module.unpack_image(archive,tmp_path/'safe',enforce_user=False)
    assert result['user']=='0'
    assert (tmp_path/'safe/0/safe.txt').read_bytes()==b'data'
    image(archive,'../escape')
    with pytest.raises(ValueError,match='Unsafe'):
        module.unpack_image(archive,tmp_path/'bad',enforce_user=False)


def test_retained_untagged_versions_are_included_and_deduplicated():
    raw = b'{}'
    import hashlib
    digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
    versions = registry.retained_versions(lambda page: [{'name': digest}, {'name': digest}])
    def request(url):
        if '/tags/' in url: return {'tags': []}, {}, b''
        return {}, {'Docker-Content-Digest': digest}, raw
    result = registry.inventory(request, versions)
    assert result['retained_version_count'] == 1
    assert result['images'][0]['digest'] == digest


def test_version_lookup_failure_is_not_an_empty_inventory():
    def denied(page): raise PermissionError('denied')
    with pytest.raises(PermissionError): registry.retained_versions(denied)
    with pytest.raises(ValueError): registry.retained_versions(lambda page: [{'name': 'not-a-digest'}])




def test_unavailable_inventory_is_scoped_to_exact_endpoints():
    from urllib.error import HTTPError
    url = 'https://api.github.com/orgs/hyperme-sh/packages/container/auth-service%2Fruntime/versions?page=1'
    assert registry.unavailable(HTTPError(url, 404, 'missing', {}, None))
    assert not registry.unavailable(HTTPError(url, 500, 'server', {}, None))
    assert not registry.unavailable(HTTPError(url.replace('auth-service', 'other'), 404, 'missing', {}, None))
    assert not registry.unavailable(HTTPError(url.replace('api.github.com', 'other.invalid'), 404, 'missing', {}, None))


def test_historical_configuration_is_recorded_without_skipping_layers(tmp_path):
    import io
    import tarfile
    spec = importlib.util.spec_from_file_location('inspect_configured', ROOT / 'scripts/inspect-container.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode='w') as archive:
        member = tarfile.TarInfo('old.txt')
        member.size = 3
        archive.addfile(member, io.BytesIO(b'old'))
    image = tmp_path / 'image.tar'
    with tarfile.open(image, 'w') as archive:
        files = {'manifest.json': json.dumps([{'Config': 'config.json', 'Layers': ['layer.tar']}]).encode(),
                 'config.json': json.dumps({'config': {'User': '65532:65532', 'Env': ['HYPERMESH_REGION=test']}}).encode(),
                 'layer.tar': layer.getvalue()}
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    result = module.unpack_image(image, tmp_path / 'historical', enforce_user=False)
    assert result['configured_environment_names'] == ['HYPERMESH_REGION']
    assert (tmp_path / 'historical/0/old.txt').read_bytes() == b'old'
    assert (tmp_path / 'historical/image-config.json').is_file()
    with pytest.raises(ValueError, match='configuration'):
        module.unpack_image(image, tmp_path / 'current')
