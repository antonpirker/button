#!/usr/bin/python

import json
import pytz
import sys
import time
import datetime

import gspread
from oauth2client.service_account import ServiceAccountCredentials

from scapy.all import *


GDOCS_SPREADSHEET_NAME = 'Baby Tracking'
GDOCS_OAUTH_JSON = 'baby-tracking-7eb0941024f8.json' # this was optained from https://console.developers.google.com/apis/api?project=baby-tracking

DASH_SOMAT = 'ac:63:be:c6:5b:8d'
DASH_PERSIL = 'ac:63:be:da:1f:7a'


def login_open_sheet(oauth_key_file, spreadsheet):
    try:
        json_key = json.load(open(oauth_key_file))
        scope = ['https://spreadsheets.google.com/feeds']
        credentials = ServiceAccountCredentials.from_json_keyfile_name(oauth_key_file, scope)

        gc = gspread.authorize(credentials)
        worksheet = gc.open(spreadsheet).sheet1
        return worksheet
    except Exception as ex:
        print('Unable to login and get spreadsheet.  Check OAuth credentials, spreadsheet name, and make sure spreadsheet is shared to the client_email address in the OAuth .json file!')
        print('Google sheet login failed with error:', ex)
        sys.exit(1)


def record_message(message):
    vienna = pytz.timezone('Europe/Vienna')
    timestamp = datetime.now(vienna)
    values = [timestamp, message]
    worksheet.insert_row(values, 2)


def arp_display(pkt):
    if pkt.haslayer(DHCP):
        if pkt[Ether].src == DASH_SOMAT:
            print "Aufgewacht"
            record_message('Aufgewacht')

        elif pkt[Ether].src == DASH_PERSIL:
            print "In die Windeln gemacht"
            record_message('In die Windeln gemacht')

        else:
            print "BOOTP from other device: %s" % pkt[Ether].src


print('Logging Amazon Dash Button presses to {0}.'.format(GDOCS_SPREADSHEET_NAME))
print('Press Ctrl-C to quit.')
worksheet = None

# Login if necessary.
if worksheet is None:
    worksheet = login_open_sheet(GDOCS_OAUTH_JSON, GDOCS_SPREADSHEET_NAME)

print sniff(prn=arp_display, filter="(udp and (port 67 or 68))", store=0, count=0)

