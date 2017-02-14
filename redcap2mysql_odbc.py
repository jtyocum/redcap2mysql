#!/usr/bin/python

# Export data from a REDCap project and send to a MySQL database.
# Track changes to transferred data files in local git repository.
#
# This is just a *rough* prototype in the *early* stages of development.
#
# It has been tested on ActivePython 64 for Windows on Windows Server 2008 R2.
# It has also been tested on Ubuntu 16 using the vendor-supplied 64-bit Python.
#
# You need to have a REDCap project and a MySQL database. MySQL
# access will be over SSL, so you need an SSL key and certs.
#
# Requires Python 2.7, a config file, git, mysql, a DSN, and these packages:
#
# python -m pip install pandas
# python -m pip install sqlalchemy
# python -m pip install ConfigParser
# python -m pip install pymysql
# python -m pip install pycurl
# python -m pip install logging
# python -m pip install pytz
# python -m pip install datetime
# python -m pip install gitpython
# python -m pip install --user -e git+https://github.com/alorenzo175/mylogin.git#egg=mylogin
# python -m pip install pyodbc
# python -m pip install certifi
#
# On Windows, you will also need Microsoft Visual C++ Compiler for Python 2.7.
# https://www.microsoft.com/en-us/download/details.aspx?id=44266
#
# Usage: python redcap2mysql.py [Project] [...]
#
# ... Where Project contains letters, numbers, and underscore characters. More
#     than one project may be listed, with spaces separating the project names.
#
# This script can be automated with a utility such as cron. Here is an example
# crontab entry which runs the script every day at 8:55 PM:
#
# 55 20 * * * (cd /path/to/folder; /usr/bin/python ./redcap2mysql.py)
#
# Todo:
#
# 1. Add input data validation for all configuration parameters.
# 2. Try to conform to Python coding styles, conventions, and best practices.

# Use Python 3 style print statements.
from __future__ import print_function

# Import packages
import ConfigParser
import pyodbc
from sqlalchemy import *
from sys import exit
import os
import sys
from pandas.io import sql
import getpass
import pandas as pd
import certifi
import pycurl
from urllib import urlencode
import hashlib
import logging
import socket
from StringIO import StringIO
import pytz
from datetime import datetime
import re
import git
import traceback

# --------------
# Configuration
# --------------

config_file = 'conf/redcap2mysql.cfg'   # See conf/redcap2mysql.cfg.example
log_level = logging.DEBUG               # Set to logging.DEBUG or logging.INFO

# Configure parameters with defaults. Use a config file for most of these.
config = ConfigParser.SafeConfigParser(
    {'data_path': 'data', 'log_file': 'redcap2mysql.log',
     'log_timestamp_format': '%Y-%m-%d %H:%M:%S %Z', 'mysql_dsn': '', 
     'mysql_host': 'localhost', 'mysql_user': '', 'mysql_pwd': '',
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
mysql_dsn = config.get('mysql', 'mysql_dsn', 0)
mysql_host = config.get('mysql', 'mysql_host', 0)
mysql_user = config.get('mysql', 'mysql_user', 0)
redcap_url = config.get('redcap', 'redcap_url', 0)
redcap_key = config.get('redcap', 'redcap_key', 0)
redcap_event_name_maxlen = int(
    config.get('redcap', 'redcap_event_name_maxlen', 0))

# Set log level and timestamp format
logging.basicConfig(filename=log_file, level=logging.DEBUG,
    format='%(asctime)s %(message)s', datefmt=log_timestamp_format)

# Create a local git repository for downloading and archiving data.
try:
    repo = git.Repo.init(data_path)
except:
    message = "Can't create git repo (%s)! Check config file." % (data_path)
    logging.warning(message)
    raise OSError(message)

# Create data folder. Should already exist if git repo created without error.
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

# Two ways to get the password are supported.
#
# From least secure to most secure, these are:
#
# 1. Read clear-text password from config file.
# 2. Read password as entered manually from a console prompt.

# First try the config file. This is the least secure method. Protect the file.
mysql_pwd = config.get('mysql', 'mysql_pwd', 0)

# Try other method if config file password is blank or missing.
if mysql_pwd == '':
    # Prompt for the password. More secure, but won't work unattended.
    mysql_pwd = getpass.getpass()

# ---------------------------
# Create database connection
# ---------------------------

DB_URI = "mysql+pyodbc://{user}:{password}@{dsn}"
conn = create_engine(
    DB_URI.format( user=mysql_user, password=mysql_pwd, dsn=mysql_dsn ))

# -----------------
# Define functions
# -----------------

def get_data(csv_file, redcap_key, redcap_url, content):
    """Get REDCap data as a CSV file with an API key, URL and content type."""
    with open(csv_file, 'wb') as f:
        c = pycurl.Curl()
        c.setopt(pycurl.CAINFO, certifi.where())
        c.setopt(c.URL, redcap_url)
        c.setopt(c.FOLLOWLOCATION, True)
        post_data = {'token': redcap_key, 'content': content, \
                     'rawOrLabel': 'raw', 'type': 'flat', 'format': 'csv', \
                     'exportSurveyFields': 'True'}
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

def get_prev_hash(project, mysql_table, log_table, conn = conn):
    """Get the sha1 hash of the previously uploaded data for a table."""

    # See if the database contains the log_table (REDCap transfer log) table.
    rs = sql.execute('SHOW TABLES LIKE "' + log_table + '";', conn)
    row0 = rs.fetchone()
    res = ''
    if (row0 is not None) and (len(row0) != 0):
        res = row0[0]

    # If the table is found, find the most recent hash for the table data.
    prev_hash = ''
    if res == log_table:
        sql_cmd = 'SELECT sha1_hash FROM %s ' % log_table + \
                  'WHERE table_name = "%s" ' % mysql_table + \
                  'ORDER BY timestamp_utc DESC ' + \
                  'LIMIT 1;'
        rs = sql.execute(sql_cmd, conn)
        row0 = rs.fetchone()
        if (row0 is not None) and (len(row0) != 0):
            prev_hash = row0[0]

    return(prev_hash)

def parse_csv(csv_file):
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

def hash_file(file_name):
    """Create a hash of a file."""
    BLOCKSIZE = 65536
    hasher = hashlib.sha1()
    with open(file_name, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    return(hasher.hexdigest())

def send_to_db(data_path, project, csv_file, dataset, mysql_table, log_table,
               redcap_key = redcap_key, redcap_url = redcap_url,
               conn = conn, mysql_user = mysql_user,
               redcap_event_name_maxlen = redcap_event_name_maxlen):
    """Send data from REDCap to a MySQL (or MariaDB) database."""

    if project != '':
        # Prepend project name.
        csv_file = project + '_' + csv_file
        mysql_table = project + '_' + mysql_table
        log_table = project + '_' +  log_table

    # Prepend file_path to csv_file.
    csv_file = os.path.join(data_path, csv_file)

    # Get the data from REDCap.
    if project != '':
        redcap_key = config.get('redcap', project + '_' + 'redcap_key', 0)
    get_data(csv_file, redcap_key, redcap_url, dataset)
    data = parse_csv(csv_file)

    # Calculate the file size and a hash (checksum) for recording in the log.
    csv_file_size = os.path.getsize(csv_file)
    csv_file_hash = hash_file(csv_file)

    # If dataset == 'metadata' and csv_file_hash does not match the
    # previous value ("prev_hash", for the more recent update), then save
    # the old rcmeta and rcform tables with a datestamped name suffix
    # and create new tables for 'metadata' for 'record' data.
    prev_hash_same = False
    prev_hash = get_prev_hash(project, mysql_table, log_table)
    if csv_file_hash == prev_hash:
        prev_hash_same = True
    else:
        if prev_hash != '' and dataset == 'metadata':
            timestamp = '{:%Y%m%dT%H%M%SZ}'.format(
                datetime.utcnow().replace(tzinfo=pytz.utc))
            rs = sql.execute('RENAME TABLE %s TO %s;' % \
                (rcform, rcform + '_' + timestamp), conn)
            rs = sql.execute('RENAME TABLE %s TO %s;' % \
                (mysql_table, mysql_table + '_' + timestamp), conn)

    # If the data has changed since the last sync, write to database and log.
    if prev_hash_same == False:
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
        data.to_sql(name = mysql_table, con = conn, if_exists = 'replace',
            index = False, dtype = data_dtype_dict)

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
        log_df.to_sql(name = log_table, con = conn, if_exists = 'append',
            index = False, dtype = {'timestamp_utc':DateTime})

        # Write the log message to the log file.
        logging.info("to " + log_table + ": " + log_str)

def commit_changes(repo, project = ''):
    """Track changes to transferred data files in local git repository."""
    cmd = repo.git
    cmd.add(all=True)
    try:
        cmd.commit(m="redcap2mysql.py data sync for project " + project)
    except git.exc.GitCommandError, err:
        logging.info([traceback.format_exc(limit=1).splitlines()[-1]])

def send_data(data_path, project = ''):
    """Get REDCap data and send to MySQL."""

    # Send metadata
    send_to_db(data_path, project, 'rcmeta.csv', 'metadata', 'rcmeta', 'rcxfer', 'rcform')

    # Send events
    send_to_db(data_path, project, 'rcevent.csv', 'event', 'rcevent', 'rcxfer')

    # Send users
    send_to_db(data_path, project, 'rcuser.csv', 'user', 'rcuser', 'rcxfer')

    # Send arms
    send_to_db(data_path, project, 'rcarm.csv', 'arm', 'rcarm', 'rcxfer')

    # Send Form Event Mappings (fems)
    # ERROR: You cannot export form/event mappings for classic projects
    #send_to_db(project, data_path, 'rcfem.csv', 'formEventMapping', 'rcfem', 'rcxfer')

    # Send instruments
    send_to_db(data_path, project, 'rcinst.csv', 'instrument', 'rcinst', 'rcxfer')

    # Send records
    send_to_db(data_path, project, 'rcform.csv', 'record', 'rcform', 'rcxfer')

    # Commit changes to local repo
    commit_changes(repo, project)

# --------------
# Transfer data
# --------------

# Get the project name(s) from the script argument(s), if present.
# The project must only contain letters, numbers, and underscore characters.
if len(sys.argv) > 1:
    pattern = re.compile('^[A-Za-z0-9_]+$')
    for x in sys.argv[1:]:
        if pattern.match(sys.argv[1]):
            project = sys.argv[1]
            send_data(data_path, project)
        else:
            print("Invalid project name: " + project)
            exit(5)
else:
    send_data(data_path)
