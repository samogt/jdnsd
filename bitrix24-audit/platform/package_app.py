"""Build a self-contained Windows ZIP from the official embedded CPython distribution."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import urllib.request
import zipfile

parser=argparse.ArgumentParser()
parser.add_argument('--output',required=True)
parser.add_argument('--source-commit',required=True)
parser.add_argument('--extract-to')
options=parser.parse_args()
root=Path(__file__).resolve().parent
url='https://www.python.org/ftp/python/3.14.10/python-3.14.10-embed-amd64.zip'
with tempfile.TemporaryDirectory(prefix='bitrix-package-') as temporary:
    temporary=Path(temporary);runtime_zip=temporary/'python.zip'
    urllib.request.urlretrieve(url,runtime_zip)
    runtime_hash=hashlib.sha256(runtime_zip.read_bytes()).hexdigest()
    package=temporary/'package';(package/'.runtime').mkdir(parents=True)
    with zipfile.ZipFile(runtime_zip) as archive:
        if archive.testzip():raise RuntimeError('Invalid runtime ZIP')
        for name in archive.namelist():
            if Path(name).is_absolute() or '..' in Path(name).parts:raise RuntimeError('Invalid runtime path')
        archive.extractall(package/'.runtime')
    for name in ('python.exe','_sqlite3.pyd','sqlite3.dll','python314.zip'):
        if not (package/'.runtime'/name).is_file():raise RuntimeError('Runtime missing '+name)
    pth=package/'.runtime'/'python314._pth'
    pth.write_text(pth.read_text(encoding='utf-8')+'\n..\n',encoding='utf-8')
    for name in ('app.py','engine.py','adapters.py','demo.py','index.html','START_GUI.cmd','START.ps1','README.md'):
        shutil.copyfile(root/name,package/name)
    manifest={'version':'2.0.0','source_commit':options.source_commit,'runtime_url':url,'runtime_sha256':runtime_hash,'files':{}}
    for file in sorted(package.rglob('*')):
        if file.is_file():manifest['files'][file.relative_to(package).as_posix()]=hashlib.sha256(file.read_bytes()).hexdigest()
    (package/'build_manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    target=Path(options.output);target.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for file in sorted(package.rglob('*')):
            if file.is_file():archive.write(file,file.relative_to(package).as_posix())
    if options.extract_to:
        destination=Path(options.extract_to);destination.mkdir(parents=True,exist_ok=True)
        with zipfile.ZipFile(target) as archive:archive.extractall(destination)
    print('BUNDLE BUILT',target.stat().st_size,'bytes; runtime SHA256',runtime_hash,'; archive SHA256',hashlib.sha256(target.read_bytes()).hexdigest())
