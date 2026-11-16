"""Publish a previously qualified image; authentication is supplied only by CI."""
import argparse
import json
import re
import subprocess

REGISTRY_IMAGE = 'ghcr.io/hyperme-sh/auth-service/runtime'


def publication_plan(revision, image_id, channel, version=None):
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Expected full qualified source revision')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise ValueError('Expected qualified local image ID')
    if channel == 'test' and version is None:
        tags = ['test']
    else:
        raise ValueError('Only the moving test channel is authorized')
    return {'image_id': image_id, 'revision': revision,
            'targets': [REGISTRY_IMAGE + ':' + tag for tag in tags]}


def publish(plan, run=subprocess.run):
    result = run(['docker', 'image', 'inspect', plan['image_id']],
                 check=True, capture_output=True, text=True)
    inspected, = json.loads(result.stdout)
    if (inspected['Id'] != plan['image_id'] or
            inspected['Config'].get('Labels', {}).get('org.opencontainers.image.revision') != plan['revision']):
        raise ValueError('Qualified image identity or revision changed')
    for target in plan['targets']:
        try:
            run(['docker', 'tag', plan['image_id'], target], check=True)
            run(['docker', 'push', target], check=True)
            # Fetch the registry tag without running it, then compare qualified bytes.
            run(['docker', 'pull', target], check=True)
            remote = run(['docker', 'image', 'inspect', target],
                         check=True, capture_output=True, text=True)
            published, = json.loads(remote.stdout)
            if published['Id'] != plan['image_id']:
                raise ValueError('Published tag differs from qualified image')
            print(json.dumps({'published': target, 'image_id': published['Id'],
                              'registry_digests': published.get('RepoDigests', []),
                              'revision': plan['revision']}))
        finally:
            run(['docker', 'image', 'rm', target], check=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--revision', required=True)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--channel', choices=['test'], required=True)
    parser.add_argument('--version')
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    plan = publication_plan(args.revision, args.image_id, args.channel, args.version)
    print(json.dumps(plan, indent=2))
    if args.publish:
        publish(plan)
