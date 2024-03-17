#!/usr/bin/env python3
#
#
# Program that accepts a (LARGE) xml file and convert it to 
# easy-to-process comma separated key=value pair format 
# (line oriented splunk friendly record format)
#
# Usage: dmarc-parser.py <input xml file> 1> outfile
# Returns 0 for success and 1 for errors. 
# Error messages are directed to stderr
#
# Patterned after a tool by Author Binu P. Ramakrishnan at Yahoo 09/12/2014 (New BSD Licence)

import sys
import xml.etree.cElementTree as etree
import argparse
import socket
import datetime

# Fields are (longname, shortname, width, verbosity)
metadata_fields = [
  ('org_name','orgainzation', 6, 0),
  ('email','          email', 6, 1),
  ('extra_contact_info','extra', 6, 2),
  ('report_id', 'report_id', 6, 2),
]
metadata_dates = [
  ('date_range/Begin','             Begin', 6, 0),
  ('date_range/begin','Begin', 6, 2),
  ('date_range/End','               End', 6, 0),
  ('date_range/end','End', 6, 2),
]
policy_fields = [
  ('domain','domain', 6, 0),
  ('adkim','adkim', 6, 0),
  ('aspf','aspf', 6, 0),
  ('p','p', 6, 0),
  ('pct','pct', 6, 0),
]
record_fields =  [
  ('row/source_ip','source_ip', 6, 0),
  ('row/count','count', 6, 0),
  ('row/policy_evaluated/disposition','dispos', 6, 1),
  ('row/policy_evaluated/dkim','dkim PE', 6, 1),
  ('row/policy_evaluated/spf','spf PE', 6, 1),
  ('row/policy_evaluated/reason/type','reason', 6, 1),
  ('row/policy_evaluated/reason/comment','comment', 6, 1),
  ('identifiers/envelope_to','envelope_to', 6, 0),
  ('identifiers/header_from','header_from', 6, 0),
  ('auth_results/dkim/domain','AR dkim dom', 6, 0),
  ('auth_results/dkim/result','AR dkim res', 6, 0),
  ('auth_results/dkim/human_result','AR dkim hum', 6, 0),
  ('auth_results/spf/domain','AR spf domain', 6, 0),
  ('auth_results/spf/result','AR spf res', 6, 0),
]

def convert_date(d):
  """Converts string seconds since the epoch to local time"""
  return (datetime.datetime.fromtimestamp(int(d)).isoformat())
  
def process_records(context, args):

  meta_data = {}
  for event, elem in context:
    if event == "end" and elem.tag == "report_metadata":
      for i, _, _, _ in metadata_fields:
        meta_data[i] = elem.findtext(i, None)
      meta_data['date_range/Begin'] =  convert_date(elem.findtext('date_range/begin', None))
      meta_data['date_range/End'] =  convert_date(elem.findtext('date_range/end', None))

    if event == "end" and elem.tag == "policy_published":
      for i, _, _, _  in policy_fields:
        meta_data[i] = elem.findtext(i, None)


    if event == "end" and elem.tag == "record":
      record = meta_data.copy()  # Caution, assumes metadata came first

      # process record elements
      # NOTE: This may require additional input validation
      for i, _, _, _ in record_fields:
        record[i] = elem.findtext(i, None)
      schema = metadata_fields + metadata_dates + policy_fields + record_fields
      if args.verbose > 2:
        print (f'Schema: {schema}')
        print (f'Record: {record}')
      print_record(record, schema=schema)
  return;


global once
once=True
def print_record(record, schema=None):
  """Print records, CSV style"""
  global once
  
  if schema == None:
    schema = list(record)

  if once:
    once=False
    for s, sn, w, ver in schema:
      if ver <= args.verbose:
        print (sn, end=', ')
    print ()
  for s, sn, w, ver in schema:
    if ver <= args.verbose:
      try: v=record[s]
      except KeyError: v=None
      print (v, end=', ')
  print ()

def main():
  global args
  options = argparse.ArgumentParser(epilog="Example: %(prog)s dmarc-xml-file 1> outfile.log")
  options.add_argument("dmarcfile", help="dmarc file in XML format")
  options.add_argument('-v', '--verbose', default=0, action='count');
  args = options.parse_args()

  process_records(iter(etree.iterparse(args.dmarcfile, events=("start", "end"))), args)

if __name__ == "__main__":
  main()
