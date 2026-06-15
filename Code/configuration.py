import sys
import logging
from configparser import ConfigParser
from pathlib import Path
from dotenv import load_dotenv
import os
import multiprocessing as mp


from dotenv import load_dotenv
load_dotenv('.env')

USER = os.getenv('GITHUB_USER')
TOKEN = os.getenv('GITHUB_TOKEN')

SAMPLE_LIMIT = 0
NUM_WORKERS = 8
PROSPECTOR_WORKERS = min(mp.cpu_count() - 1, 5) # Anything more than 20 will result in rate limits.
DB_WORKERS = mp.cpu_count() - 1
LOGGING_LEVEL = logging.WARNING

PROSPECTOR_PYTHON_PATH = os.getenv('PROSPECTOR_PYTHON_PATH')
MINIMUM_COMMIT_SCORE = os.getenv('MIN_COMMIT_SCORE', 65)
PROSPECTOR_BACKEND_ADDRESS = os.getenv('PROSPECTOR_BACKEND_ADDRESS')
PROSPECTOR_PATH = os.getenv('PROSPECTOR_PATH')
PROSPECTOR_GIT_CACHE = os.getenv('PROSPECTOR_GIT_CACHE', '/tmp/gitcache')
# PROSPECTOR_GIT_CACHE = os.getenv('PROSPECTOR_GIT_CACHE', '/ssddata/user/tmp/')
PATCH_FILE_STORAGE_PATH = os.getenv('PATCH_FILE_STORAGE_PATH', '/pool0/data/user/cvedataset-patches/')
HARDWARE_RESOURCE_THRESHOLD_PERCENT = 90

MAXIMUM_PATCH_SIZE_FOR_DB_STORAGE = 1024 * 1024  # 1MB

log_level_map = {'DEBUG': logging.DEBUG,
                 'INFO': logging.INFO,
                 'WARNING': logging.WARNING,
                 'ERROR': logging.ERROR,
                 'CRITICAL': logging.CRITICAL
                 }

logging.basicConfig(level=LOGGING_LEVEL,
                    format='%(asctime)s %(name)s %(levelname)s %(message)s',
                    datefmt='%m/%d/%Y %H:%M:%S')
logger = logging.getLogger('MoreFixes')
logger.removeHandler(sys.stderr)

logger.setLevel(LOGGING_LEVEL)
logging.getLogger("requests").setLevel(LOGGING_LEVEL)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("urllib3.connection").setLevel(logging.WARNING)
logging.getLogger("pathlib").setLevel(LOGGING_LEVEL)
logging.getLogger("subprocess").setLevel(LOGGING_LEVEL)
logging.getLogger("h5py._conv").setLevel(logging.WARNING)
logging.getLogger("git.cmd").setLevel(LOGGING_LEVEL)
logging.getLogger("github.Requester").setLevel(LOGGING_LEVEL)
