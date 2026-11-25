"""PyInstaller 入口 —— 让 __main__.py 里的相对导入在打包后仍然成立。"""

import sys

from skyhuiyu.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
