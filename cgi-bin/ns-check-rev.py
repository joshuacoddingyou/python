#!/usr/bin/python

"""
ns-check-rev.py
(c) by Joshua G. David, joshuafreela@gmail.com

CGI-BIN for On-line checking of certificates -
a handler for URL in Netscape extension nsRevocationUrl.

Have look at a x509_extensions-section and the
attributes nsBaseUrl and nsRevocationUrl

Input:

PATH_INFO
- Name of CA in openssl.cnf (section [ca] of openssl.cnf)
QUERY_STRING
- Serial number of desired certificate
  max. 8 digits hexadecimal (32 Bit)

Examples:
  ns-check-rev.py/Persona?537A
  checks if certificate number 0x537A issued of CA "Persona" is valid

Output:

  Content-type: application/x-netscape-revocation
  0 if certificate is valid <=> V in index.txt
  1 if certificate is invalid
"""

Version='0.6.6'

import sys, os, string, re, pycacnf, htmlbase, openssl

from pycacnf import opensslcnf, pyca_section

request_method  = os.environ['REQUEST_METHOD']
query_string    = os.environ['QUERY_STRING']
ca_name = os.environ.get('PATH_INFO','')[1:]

sys.stdin.close()

rm = (re.compile('[0-9a-fA-F]+')).match(query_string)
if (request_method!='GET') or \
   (len(query_string)>8) or \
   not rm or \
   rm.group(0)!=query_string:
  sys.exit(0)

if not ca_name:
  htmlbase.PrintErrorMsg('No certificate authority.')
  sys.exit(0)

if not opensslcnf.data['ca'].has_key(ca_name):
  htmlbase.PrintErrorMsg('Unknown certificate authority "%s"!' % ca_name)
  sys.exit(0)

ca_section=opensslcnf.data[opensslcnf.data['ca'][ca_name]]
ca_dir = ca_section.get('dir','')
ca_database = string.replace(ca_section.get('database','$dir/index.txt'),'$dir',ca_dir)

serialnumber=string.atoi(query_string,16)

entry = openssl.db.GetEntrybySerial(ca_database,serialnumber)

print 'Content-type: application/x-netscape-revocation\n'

if not entry:
  print 1
  sys.exit(0)

print not (entry and openssl.db.IsValid(entry))

sys.exit(0)

