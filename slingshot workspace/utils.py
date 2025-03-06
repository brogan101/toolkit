import logging
import os
import sys
import ctypes
import pkg_resources

def setup_logging():
    logging.basicConfig(
        filename='slingshot.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger('SlingShot')

logger = setup_logging()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def run_as_admin():
    script = os.path.abspath(sys.argv[0])
    params = ' '.join([script] + sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit(0)

def check_dependencies():
    required = {'psutil', 'customtkinter'}
    installed = {pkg.key for pkg in pkg_resources.working_set}
    missing = required - installed
    if missing:
        logger.error(f"Missing dependencies: {missing}")
        print(f"Please install missing dependencies: {missing}")
        print(f"Run: pip install {' '.join(missing)}")
        sys.exit(1)
    logger.info("All dependencies satisfied.")