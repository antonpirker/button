#!/usr/bin/python
# coding=UTF-8

from __future__ import unicode_literals

import json
import pytz
import os
import sys
import time
import datetime

import gspread
from oauth2client.service_account import ServiceAccountCredentials

from scapy.all import *

import logging
logging.basicConfig(filename='button.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s %(filename)s:%(lineno)d')
logger = logging.getLogger(__file__)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

GDOCS_SPREADSHEET_NAME = 'Baby Tracking'
GDOCS_OAUTH_JSON = 'keys/baby-tracking-7eb0941024f8.json' # this was optained from https://console.developers.google.com/apis/api?project=baby-tracking

DASH_SOMAT = 'ac:63:be:c6:5b:8d'
DASH_PERSIL = 'ac:63:be:da:1f:7a'

MESSAGES = {
    DASH_SOMAT: 'Ich bin munter!',
    DASH_PERSIL: 'Was komisches ist passiert!',
}

def login_open_sheet(oauth_key_file, spreadsheet):
    try:
        json_key = json.load(open(os.path.join(BASE_DIR, oauth_key_file)))
        scope = ['https://spreadsheets.google.com/feeds']
        credentials = ServiceAccountCredentials.from_json_keyfile_name(oauth_key_file, scope)

        gc = gspread.authorize(credentials)
        worksheet = gc.open(spreadsheet).sheet1
        return worksheet
    except Exception as ex:
        logging.error('Unable to login and get spreadsheet.  Check OAuth credentials, spreadsheet name, and make sure spreadsheet is shared to the client_email address in the OAuth .json file!')
        logging.error('Google sheet login failed with error:', ex)
        sys.exit(1)


def record_message(message):
    vienna = pytz.timezone('Europe/Vienna')
    timestamp = datetime.now(vienna)
    values = [timestamp.strftime('%Y-%m-%d %H:%M'), message]
    worksheet.insert_row(values, 2)


def handle_button_press(pkt):
    if pkt.haslayer(DHCP):
        try:
            key = pkt[Ether].src
            message = MESSAGES[key]
            logging.info(message)
            record_message(message)

        except KeyError:
            logging.info("BOOTP from other device: %s" % pkt[Ether].src)


logging.info('Logging Amazon Dash Button presses to {0}.'.format(GDOCS_SPREADSHEET_NAME))
logging.info('Press Ctrl-C to quit.')
worksheet = None

# Login if necessary.
if worksheet is None:
    worksheet = login_open_sheet(GDOCS_OAUTH_JSON, GDOCS_SPREADSHEET_NAME)

try:
    response = sniff(prn=handle_button_press, filter="(udp and (port 67 or 68))", store=0, count=1)
    logging.info(response)
except:
    logging.exception('')
