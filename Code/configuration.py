import sys
import logging
from configparser import ConfigParser
from pathlib import Path
from dotenv import load_dotenv
import os
import multiprocessing as mp

load_dotenv('.env')
# set sensible defaults for thTe configurable fields
DATA_PATH = 'Data'
DATABASE_NAME = 'CVEfixes_sample.db'
USER = os.getenv('GITHUB_USER', None)
TOKEN = os.getenv('GITHUB_TOKEN', None)
SAMPLE_LIMIT = 0
NUM_WORKERS = 8
PROSPECTOR_WORKERS = min(mp.cpu_count() - 1, 15) # Anything more than 20 will result in rate limits.
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

# full path to the .db file
DATABASE = Path(DATA_PATH) / DATABASE_NAME
config_read = False

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


def read_config() -> None:
    """
    Read CVEfixes configuration from .CVEfixies.ini, $HOME/.config/CVEfixes.ini or $HOME/.CVEfixes.ini

    Sets global constants with values found in the ini file.
    """
    global DATA_PATH, DATABASE_NAME, DATABASE, USER, TOKEN, SAMPLE_LIMIT, NUM_WORKERS, LOGGING_LEVEL, config_read

    config = ConfigParser()
    if not config.read(['.CVEfixes.ini',
                        Path.home() / '.config' / 'CVEfixes.ini',
                        Path.home() / '.CVEfixes.ini']):
        logger.warning('Cannot find CVEfixes config file in the working or $HOME directory, see INSTALL.md')

    # try and update settings for each of the values, use
    DATA_PATH = config.get('CVEfixes', 'database_path', fallback=DATA_PATH)
    DATABASE_NAME = config.get('CVEfixes', 'database_name', fallback=DATABASE_NAME)
    USER = config.get('GitHub', 'user', fallback=USER)
    TOKEN = config.get('GitHub', 'token', fallback=TOKEN)
    SAMPLE_LIMIT = config.getint('CVEfixes', 'sample_limit', fallback=SAMPLE_LIMIT)
    NUM_WORKERS = config.getint('CVEfixes', 'num_workers', fallback=NUM_WORKERS)
    Path(DATA_PATH).mkdir(parents=True, exist_ok=True)  # create the directory if not exists.
    DATABASE = Path(DATA_PATH) / DATABASE_NAME
    LOGGING_LEVEL = log_level_map.get(config.get('CVEfixes', 'logging_level', fallback='WARNING'), logging.WARNING)
    config_read = True


if not config_read:
    read_config()
    logger.setLevel(LOGGING_LEVEL)
    logging.getLogger("requests").setLevel(LOGGING_LEVEL)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connection").setLevel(logging.WARNING)
    logging.getLogger("pathlib").setLevel(LOGGING_LEVEL)
    logging.getLogger("subprocess").setLevel(LOGGING_LEVEL)
    logging.getLogger("h5py._conv").setLevel(logging.WARNING)
    logging.getLogger("git.cmd").setLevel(LOGGING_LEVEL)
    logging.getLogger("github.Requester").setLevel(LOGGING_LEVEL)
