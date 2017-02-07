#!/usr/bin/python

# Export data from a REDCap project and send to a MySQL database.
# This is just a *rough* prototype in the *early* stages of development.
#
# You need to have a REDCap project and a MySQL database. MySQL
# access will be over SSL, so you need an SSL key and certs.
#
# Requires Python 2.7, a config file, and the packages imported below.
#
# This script can be automated with a utility such as cron. Here is an example
# crontab entry whcu runs the script every day at 8:55 PM:
#
# 55 20 * * * (cd /path/to/folder; /usr/bin/python ./redcap2mysql.py)
#
# Todo:
#
# 1. Check metadata and create new table only if any structural changes.
#    - Use metadata hash from log and compare against has from new metadata.
# 2. Implement local version control for archive of downloaded CSV files.

# Use Python 3 style print statements.
from __future__ import print_function

# Import packages
import ConfigParser
import mysql.connector
from mysql.connector.constants import ClientFlag
from sqlalchemy import *
from sys import exit
import os
import mylogin
from pandas.io import sql
import getpass
import pandas as pd
import pycurl
from urllib import urlencode
import hashlib
import logging
import socket
from StringIO import StringIO
import pytz
from datetime import datetime
import re

# Module installation hints:
# pip install --user -e git+https://github.com/alorenzo175/mylogin.git#egg=mylogin

# --------------
# Configuration
# --------------

# Todo: Add input data validation for all configuration parameters.

config_file = 'conf/redcap2mysql.cfg'   # See conf/redcap2mysql.cfg.example
log_level = logging.DEBUG               # Set to logging.DEBUG or logging.INFO

# Configure parameters with defaults. Use a config file for most of these.
config = ConfigParser.SafeConfigParser(
    {'data_path': 'data', 'log_file': 'redcap2mysql.log', 
    'log_timestamp_format': '%Y-%m-%d %H:%M:%S %Z', 'mysql_host': 'localhost', 
     'mysql_db': 'db', 'mysql_path': '', 'mysql_user': '', 'mysql_pwd': '',
     'redcap_url': 'https://localhost/API/', 'redcap_key': '0123456789ABCDEF',
     'redcap_event_name_maxlen': '100'})

if os.path.isfile(config_file) == True:
    config.read(config_file)
else:
    print("Can't find config file: " + config_file)
    exit(1)

data_path = config.get('global', 'data_path', 0)
log_timestamp_format = config.get('global', 'log_timestamp_format', 0)
log_file = config.get('global', 'log_file', 0)
mysql_host = config.get('mysql', 'mysql_host', 0)
mysql_db = config.get('mysql', 'mysql_db', 0)
mysql_path = config.get('mysql', 'mysql_path', 0)
mysql_user = config.get('mysql', 'mysql_user', 0)
redcap_url = config.get('redcap', 'redcap_url', 0)
redcap_key = config.get('redcap', 'redcap_key', 0)
redcap_event_name_maxlen = int(
    config.get('redcap', 'redcap_event_name_maxlen', 0))
ssl_ca = config.get('mysql-ssl', 'ssl_ca', 0)
ssl_cert = config.get('mysql-ssl', 'ssl_cert', 0)
ssl_key = config.get('mysql-ssl', 'ssl_key', 0)

# Set log level and timestamp format
logging.basicConfig(filename=log_file, level=logging.DEBUG, 
    format='%(asctime)s %(message)s', datefmt=log_timestamp_format)

# Create data folder
if not os.path.exists(data_path):
    try:
        os.makedirs(data_path)
    except:
        message = "Can't create folder (%s)! Check config file." % (data_path)
        logging.warning(message)
        raise OSError(message)

# Get username from the operating system, if it is blank (default).
if mysql_user == '':
    mysql_user = getpass.getuser()

# -------------------
# Get MySQL password
# -------------------

# Three ways to get the password are supported.
#
# From least secure to most secure, these are: 
#
# 1. Read clear-text password from config file.
# 2. Read encrypted password created by mysql_config_editor.
# 3. Read password as entered manually from a console prompt.

# First try the config file. This is the least secure method. Protect the file.
mysql_pwd = config.get('mysql', 'mysql_pwd', 0)

# Try other two methods if config file password is blank or missing.
if mysql_pwd == '':
    if mysql_path != '':
        # Read encrypted password and decrypt it with mylogin module.
        # While better than clear-text, be careful about securing the pw file.
        # However, it's probably the best method for unattended use.
        try:
            # Get encrypted password. This requires the mylogin module.
            login = mylogin.get_login_info(mysql_path, host=mysql_host)
            mysql_pwd = login['passwd']
        except mylogin.exception.UtilError as err:
            print("mylogin error: {0}".format(err))
    if mysql_pwd == '':
        # Prompt for the password. More secure, but won't work unattended.
        mysql_pwd = getpass.getpass()

# Configure SSL settings.
ssl_args = {
    'client_flags': [ClientFlag.SSL],
    'ssl_ca': ssl_ca,
    'ssl_cert': ssl_cert,
    'ssl_key': ssl_key,
}

# ---------------------------
# Create database connection
# ---------------------------

DB_URI = "mysql+mysqlconnector://{user}:{password}@{host}:{port}/{db}"
db = create_engine(
    DB_URI.format( user=mysql_user, password=mysql_pwd, host=mysql_host, 
        port='3306', db=mysql_db), connect_args = ssl_args )

# -----------------
# Define functions
# -----------------

def getdata(csv_file, redcap_key, redcap_url, content):
    """Get REDCap data as a CSV file with an API key, URL and content type."""
    with open(csv_file, 'wb') as f:
        c = pycurl.Curl()
        c.setopt(c.URL, redcap_url)
        c.setopt(c.FOLLOWLOCATION, True)
        post_data = {'token': redcap_key, 'content': content,
                'type': 'flat', 'format': 'csv', 'exportSurveyFields': 'True'}
        postfields = urlencode(post_data)
        c.setopt(c.POSTFIELDS, postfields)
        c.setopt(c.WRITEDATA, f)
        try:
            c.perform()
            c.close()
        except pycurl.error, err:
            c.close()
            message = "Can't fetch data. Check config file: " + config_file
            print(message)
            logging.warning(message)
            exit(2)

def parsecsv(csv_file):
    """Parse a CSV file with Pandas, with basic checks and error handling."""
    if os.path.isfile(csv_file) == True:
        try:
            data = pd.read_csv(csv_file, index_col=False)
        except pd.parser.CParserError, err:
            message = "Can't parse REDCap data. Check csv file: " + csv_file
            print(message)
            logging.warning(message)
            exit(3) 
    else:
        message = "Can't read csv file: " + csv_file
        print(message)
        logging.warning(message)
        exit(4)
    
    data.insert(0, 'id', range(1, 1 + len(data)))
    return(data)

def hashfile(file_name):
    """Create a hash of a file."""
    BLOCKSIZE = 65536
    hasher = hashlib.sha1()
    with open(file_name, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    return(hasher.hexdigest())

def send_to_db(csv_file, dataset, mysql_table, log_table, 
               redcap_key = redcap_key, redcap_url = redcap_url, 
               db_handle = db, mysql_user = mysql_user,
               redcap_event_name_maxlen = redcap_event_name_maxlen):
    """Send data from REDCap to a MySQL (or MariaDB) database.""" 
    #
    # Todo: Process one form at a time instead of all at once. See above.
    #       Replace database table if it already exists. Todo: See below.
    
    # Get the data from REDCap.
    getdata(csv_file, redcap_key, redcap_url, dataset)
    data = parsecsv(csv_file)
    
    # Calculate the file size and a hash (checksum) for recording in the log.
    csv_file_size = os.path.getsize(csv_file)
    csv_file_hash = hashfile(csv_file)
    
    # Todo: If dataset == 'metadata' and csv_file_hash does not match the
    #       previous value (for the more recent update), then save
    #       the old rcmeta and rcform tables with a datestamped name suffix
    #       and create new tables for 'metadata' for 'record' data.
    
    # Set the data type for the redcap_event_name if this column is present.
    data_dtype_dict = {}
    if 'redcap_event_name' in list(data.columns.values):
        data_dtype_dict['redcap_event_name'] = String(redcap_event_name_maxlen)
    
    # Set the data type for variables ending with _timestamp as DateTime
    r = re.compile('.*_timestamp$')
    timestamp_columns = filter(r.match, list(data.columns.values))
    for column in timestamp_columns:
        data_dtype_dict[column] = DateTime
    
    # Send the data to the database.
    data.to_sql(name=mysql_table, con=db_handle, if_exists = 'replace', 
        index=False, dtype=data_dtype_dict)
    
    # Create a ISO 8601 timestamp for logging. Use UTC for timezone consistency.
    timestamp = '{:%Y-%m-%dT%H:%M:%SZ}'.format(
        datetime.utcnow().replace(tzinfo=pytz.utc))
    
    # Create the log message string as a comma-separated list of values. 
    log_str = '{0},{1},{2},{3},{4},{5},{6},{7},{8}'.format(
        timestamp, mysql_user, socket.gethostname(), len(data.index), 
        len(data.columns), mysql_table, csv_file, csv_file_size, csv_file_hash)
    
    # Create a dataframe for the log message.
    log_df = pd.read_csv(StringIO(log_str), header=None, index_col=False)
    log_df.columns = ['timestamp_utc', 'user_name', 'host_name', 'num_rows', 
        'num_cols', 'table_name', 'file_name', 'size_bytes', 'sha1_hash']
    
    # Convert the timestamp column to the datetime data type.
    log_df.timestamp_utc = pd.to_datetime(
        log_df.timestamp_utc, yearfirst=True, utc=True)
    
    # Send the log message dataframe to the database.
    log_df.to_sql(name=log_table, con=db_handle, if_exists = 'append', 
        index=False, dtype={'timestamp_utc':DateTime})
    
    # Write the log message to the log file.
    logging.info("to " + log_table + ": " + log_str)

# --------------
# Transfer data
# --------------

# Get REDCap data and send to MySQL

# Send metadata
send_to_db(os.path.join(data_path, 'rcmeta.csv'), 'metadata', 'rcmeta', 'rcxfer')

# Send events
send_to_db(os.path.join(data_path, 'rcevent.csv'), 'event', 'rcevent', 'rcxfer')

# Send users
send_to_db(os.path.join(data_path, 'rcuser.csv'), 'user', 'rcuser', 'rcxfer')

# Send records
send_to_db(os.path.join(data_path, 'rcform.csv'), 'record', 'rcform', 'rcxfer')