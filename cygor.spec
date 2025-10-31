# cygor.spec
from PyInstaller.utils.hooks import collect_data_files, collect_all

datas = collect_data_files('cygor', includes=['web/templates/*', 'web/static/*'])
hiddenimports = []
for pkg in ['fastapi', 'sqlalchemy', 'jinja2', 'asyncpg', 'uvicorn']:
    hiddenimports += collect_all(pkg)[1]

a = Analysis(
    ['cygor/cli.py'],
    pathex=['.'],
    datas=datas,
    hiddenimports=hiddenimports,
)

pyz = PYZ(a.pure, a.zipped_data)
exe = EXE(
    pyz,
    a.scripts,
    name='cygor',
    console=True
)
# cygor.spec (fixed ending)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='cygor'
)

app = BUNDLE(
    coll,
    name='cygor.app',
    icon=None,
    bundle_identifier=None
)

