# PyInstaller hook for pydantic_core
# pydantic_core contains a Rust-compiled binary extension (_pydantic_core.so)
# that --collect-all sometimes misses. This hook ensures it's included.
from PyInstaller.utils.hooks import collect_all, copy_metadata

datas, binaries, hiddenimports = collect_all('pydantic_core')

# pydantic uses importlib.metadata to verify pydantic_core version
datas += copy_metadata('pydantic_core')
datas += copy_metadata('pydantic')

hiddenimports += ['pydantic_core._pydantic_core']
