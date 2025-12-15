# Monkey patches - import these first to register handlers globally
import zipfile_zstd  # noqa: F401 - Registers zstd compression support with zipfile module. Should not be required after upgrading to python 3.14

__version__ = "0.0.1"
