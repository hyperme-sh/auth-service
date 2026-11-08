"""Owned local wheel fixture; real uv resolution, no index, Git or provider calls."""
import csv
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('selected_overrides',ROOT/'scripts/export_selected_overrides.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def wheel(directory,name,marker,dependencies=()):
    directory.mkdir(parents=True,exist_ok=True)
    normalized=name.replace('-','_');info=normalized+'-0.1.0.dist-info'
    contents={normalized+'/__init__.py':"MARKER="+repr(marker)+'\n',
              info+'/METADATA':'Metadata-Version: 2.3\nName: '+name+'\nVersion: 0.1.0\nRequires-Python: >=3.11\n'+''.join('Requires-Dist: '+value+'\n' for value in dependencies)+'\n',
              info+'/WHEEL':'Wheel-Version: 1.0\nGenerator: isolated-override-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n'}
    record=io.StringIO();rows=csv.writer(record,lineterminator='\n')
    for key in (*contents,info+'/RECORD'):rows.writerow((key,'',''))
    contents[info+'/RECORD']=record.getvalue()
    path=directory/(normalized+'-0.1.0-py3-none-any.whl')
    with zipfile.ZipFile(path,'w') as archive:
        for key,value in contents.items():archive.writestr(key,value)
    return path


class SelectedOverrideTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def test_export_is_only_explicit_project_override_not_the_entire_lock(self):
        project=self.root/'pyproject.toml';project.write_text('[tool.uv]\noverride-dependencies=["fixture-events==0.1.0"]\n')
        self.assertEqual(module.selected(project),['fixture-events==0.1.0'])
        project.write_text('[project]\nname="fixture-project"\nversion="0.1.0"\n')
        self.assertEqual(module.selected(project),[])
        project.write_text('[tool.uv]\noverride-dependencies=["--index-url=invalid"]\n')
        with self.assertRaises(ValueError):module.selected(project)

    def test_selected_direct_url_overrides_transitive_pin_in_wheel_and_rebuilt_install(self):
        old=wheel(self.root/'old','fixture-events','old')
        new=wheel(self.root/'selected','fixture-events','selected')
        core=wheel(self.root/'core','fixture-core','core',['fixture-events @ '+old.as_uri()])
        dependencies=['fixture-events @ '+new.as_uri(),'fixture-core @ '+core.as_uri()]
        built=wheel(self.root/'built','fixture-auth','built',dependencies)
        rebuilt=wheel(self.root/'rebuilt','fixture-auth','rebuilt',dependencies)
        constraints=self.root/'constraints.txt';constraints.write_text('fixture-events @ '+new.as_uri()+'\nfixture-core @ '+core.as_uri()+'\n')
        project=self.root/'pyproject.toml';project.write_text('[tool.uv]\noverride-dependencies='+json.dumps(['fixture-events @ '+new.as_uri()])+'\n')
        overrides=self.root/'overrides.txt';overrides.write_text('\n'.join(module.selected(project))+'\n')
        subprocess.run(['uv','venv','--no-config','--no-project','--offline','--python',sys.executable,str(self.root/'venv')],check=True,capture_output=True,text=True)
        python=self.root/'venv/bin/python'
        command=['uv','pip','install','--no-config','--offline','--no-index','--python',str(python),'--constraint',str(constraints)]
        rejected=subprocess.run([*command,str(built)],capture_output=True,text=True)
        self.assertNotEqual(rejected.returncode,0,'constraints alone must reproduce the conflicting direct URL case')
        for artifact,marker in ((built,'built'),(rebuilt,'rebuilt')):
            result=subprocess.run([*command,'--overrides',str(overrides),'--reinstall-package','fixture-auth',str(artifact)],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            observed=subprocess.check_output([str(python),'-I','-c','import fixture_auth,fixture_events;print(fixture_auth.MARKER,fixture_events.MARKER)'],text=True).strip()
            self.assertEqual(observed,marker+' selected')
        declared=subprocess.check_output([str(python),'-I','-c','import importlib.metadata as m;print(m.requires("fixture-core")[0])'],text=True)
        self.assertIn(old.as_uri(),declared,'override must preserve the original distribution metadata pin')


if __name__=='__main__':unittest.main()
