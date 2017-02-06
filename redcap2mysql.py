#!/usr/bin/python

# Export data from a REDCap project and send to a MySQL database.
# This is just a *rough* prototype in the *early* stages of development.

# You need to have a REDCap project and a MySQL database. MySQL
# access will be over SSL, so you need an SSL key and certs.

# Requires Python 2.7, a config file, and the packages imported below.

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
import datetime

# Module installation hints:
# pip install --user -e git+https://github.com/alorenzo175/mylogin.git#egg=mylogin

# --------------
# Configuration
# --------------

# Todo: Add input data validation for all configuration parameters.

config_file = 'conf/redcap2mysql.cfg'    # See conf/redcap2mysql.cfg.example
log_file = 'redcap2mysql.log'
logging.basicConfig(filename=log_file, level=logging.DEBUG, 
    format='%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S %Z')

# Configure parameters with defaults. Use a config file for most of these.
config = ConfigParser.SafeConfigParser(
    {'mysql_host': 'localhost', 'mysql_db': 'db',  
     'mysql_path': '', 'mysql_user': '', 'mysql_pwd': '',
     'redcap_url': 'https://localhost/API/', 'redcap_key': '0123456789ABCDEF'})

if os.path.isfile(config_file) == True:
    config.read(config_file)
else:
    print("Can't find config file: " + config_file)
    exit(1)

mysql_host = config.get('mysql', 'mysql_host', 0)
mysql_db = config.get('mysql', 'mysql_db', 0)
mysql_path = config.get('mysql', 'mysql_path', 0)
mysql_user = config.get('mysql', 'mysql_user', 0)
redcap_url = config.get('redcap', 'redcap_url', 0)
redcap_key = config.get('redcap', 'redcap_key', 0)
ssl_ca = config.get('mysql-ssl', 'ssl_ca', 0)
ssl_cert = config.get('mysql-ssl', 'ssl_cert', 0)
ssl_key = config.get('mysql-ssl', 'ssl_key', 0)

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

# --------------
# Transfer data
# --------------

# Todo:
#
# 1. Don't just remove old table, but append new data to it.
#    - Compare against log and db table to discern what data is new.
# 2. Check metadata and create new table only if any structural changes.
#    - Take hash of metadata and store in log for checking against later.
# 3. Process forms separately so a change in one form does not affect tables.


# Define functions
#
# Todo: Add docstrings

def getdata(csv_file, redcap_key, redcap_url, content):
    with open(csv_file, 'wb') as f:
        c = pycurl.Curl()
        c.setopt(c.URL, redcap_url)
        c.setopt(c.FOLLOWLOCATION, True)
        post_data = {'token': redcap_key, 'content': content,
                'type': 'flat', 'format': 'csv'}
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

def hashcsv(csv_file):
    import hashlib
    BLOCKSIZE = 65536
    hasher = hashlib.sha1()
    with open(csv_file, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    return(hasher.hexdigest())

def send_to_db(csv_file, redcap_key, redcap_url, dataset, db_handle, mysql_user, 
               mysql_table, log_table):
    #
    # Todo: Process one form at a time instead of all at once. See above.
    #       Replace database table if it already exists. Todo: Append.

    getdata(csv_file, redcap_key, redcap_url, dataset)
    data = parsecsv(csv_file)
    
    csv_file_size = os.path.getsize(csv_file)
    csv_file_hash = hashcsv(csv_file)
    
    data.to_sql(name=mysql_table, con=db_handle, if_exists = 'replace', 
        index=False)
    
    timestamp = '{:%Y-%m-%d %H:%M:%S}'.format(datetime.datetime.now())
    log_str = '{0},{1},{2},{3},{4},{5},{6},{7},{8}'.format(
        timestamp, mysql_user, socket.gethostname(), len(data.index), 
        len(data.columns), mysql_table, csv_file, csv_file_size, csv_file_hash)
    
    log_df = pd.read_csv(StringIO(log_str), header=None, index_col=False)
    log_df.columns = ['timestamp', 'user', 'host', 'num_rows', 'num_cols', 
        'table_name', 'file_name', 'size', 'hash']
    
    log_df.to_sql(name=log_table, con=db_handle, if_exists = 'append', 
        index=False)
    
    logging.info("to " + log_table + ": " + log_str)


# Get REDCap data and send to MySQL

# Send records
send_to_db('rcform.csv', redcap_key, redcap_url, 'record', 
    db, mysql_user, 'rcform', 'rcxfer')

# Send metadata
send_to_db('rcmeta.csv', redcap_key, redcap_url, 'metadata', 
    db, mysql_user, 'rcmeta', 'rcxfer')
