import sqlite3 as lite
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_connection(db_file):
	"""
	create a connection to sqlite3 database
	"""
	conn = None
	try:
		conn = lite.connect(db_file, timeout=10)  # connection via sqlite3
	except Exception as e:
		logger.error(e)
	return conn