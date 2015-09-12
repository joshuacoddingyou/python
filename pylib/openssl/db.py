#######################################################################
# openssl.db.py Version 0.6.4
# (c) by Joshua G. David, joshuafreela@gmail.com
########################################################################
# Module for OpenSSL certificate database
########################################################################

import openssl

import sys, os, string, time, re, charset

# Konstanten aus SSLeay/apps/ca.c

DB_type     = 0
DB_exp_date = 1
DB_rev_date = 2
DB_serial   = 3       # index - unique
DB_file     = 4
DB_name     = 5       # index - unique for active
DB_number   = 6

DB_TYPE_REV = 'R'
DB_TYPE_EXP = 'E'
DB_TYPE_VAL = 'V'

# Struktur eines DN
# /C=ISO-Laendercode
# /ST=Bundesstaat
# /L=Ort
# /O=Organisation
# /OU=Abteilung
# /CN=Common Name
# /Email=Mailadresse

empty_DN_dict = {'C':'','ST':'','L':'','O':'','OU':'','CN':'','Email':''}


def GetEntrybySerial(db_filename,serial):

  database=open(db_filename,'r')

  dbline=string.strip(database.readline())
  while dbline:
    dbfields=string.split(dbline,'\t')
    dbserial=string.atoi(dbfields[DB_serial],16)

    if dbserial==serial:
      return dbfields
    dbline=database.readline()

  return []

def SplitDN(DN):

  result = {}
  s = string.split(DN[1:],'/')
  for i in s:
    try:
      id,value = string.split(i,'=',1)
      result[id] = value
    except:
      pass
  return result

def IsValid(db_entry):

  # Aktuelle Zeit in GMT abholen
  gmt = time.time()
  exp_time = time.mktime(dbtime2tuple(db_entry[DB_exp_date]))

  return (db_entry[DB_type]==DB_TYPE_VAL) and (exp_time > gmt)


def GetEntriesbyDN(db_filename,DN=empty_DN_dict,casesensitive=0,onlyvalid=0):

  searchcounter = 0
  searchindex    = []
  searchregex    = {}

  for i in DN.keys():

    if DN[i]!='':
      searchindex.append(i)
      if not casesensitive:
        DN[i]=string.lower(DN[i])
      searchregex[i] = re.compile(DN[i])
      searchcounter  = searchcounter + 1

  if searchcounter==0:
    return[]

  db_file=open(db_filename,'r')

  found = []

  db_line=string.strip(db_file.readline())

  while db_line:

    db_entry = string.split(db_line,'\t')
    dnfield  = SplitDN(db_entry[DB_name])

    matchcounter = 0
    for i in searchindex:
      if dnfield.has_key(i):
        dnfield[i] = charset.asn12iso(dnfield[i])
        if not casesensitive:
	  dnfield[i] = string.lower(dnfield[i])
        matchcounter = matchcounter+(searchregex[i].search(dnfield[i])!=None)

    if matchcounter==searchcounter:
      if onlyvalid:
        if IsValid(db_entry):
          found.append(db_entry)
      else:
        found.append(db_entry)

    db_line=db_file.readline()[:-1]

  return found


def dbtime2tuple(openssltime):

  # return time.strptime(openssltime,'%y%m%d%H%M%SZ')
  # would be easier but since strptime is broken in glibc...

  openssltime=openssltime[:-1]

  year  = string.atoi(openssltime[0:2])
  if year<50:
    year=year+2000
  else:
    year=year+1900
  month = string.atoi(openssltime[2:4])
  day   = string.atoi(openssltime[4:6])
  hour  = string.atoi(openssltime[6:8])
  minute  = string.atoi(openssltime[8:10])
  if len(openssltime)>10:
    second = string.atoi(openssltime[10:12])
  else:
    second = 0

  return (year,month,day,hour,minute,second,0,0,0)

def Revoke(db_filename,serial):

  os.rename(db_filename,db_filename+'.old')

  db_old=open(db_filename+'.old','r')

  db_new=open(db_filename,'w')

  gmtstr = time.strftime('%y%m%d%H%M%SZ',time.gmtime(time.time()))

  db_line = string.strip(db_old.readline())

  while db_line:

    db_entry = string.split(db_line,'\t')

    if ((type(serial)==type([]) and \
        string.atoi(db_entry[DB_serial],16) in serial) \
         or \
       string.atoi(db_entry[DB_serial],16)==serial):

      db_entry[DB_type] = DB_TYPE_REV
      db_entry[DB_rev_date] = gmtstr

    db_new.write('%s\n' % string.join(db_entry,'\t'))

    db_line = string.strip(db_old.readline())

  db_old.close()
  db_new.close()

def Expire(db_filename,db_expiretreshold=0,db_write=1):

  if db_write:
    os.rename(db_filename,db_filename+'.old')
    db_old=open(db_filename+'.old','r')
    db_new=open(db_filename,'w')
  else:
    db_old=open(db_filename,'r')

  gmt = time.time()

  expired_db_entries = []

  db_line = string.strip(db_old.readline())

  while db_line:

    db_entry = string.split(db_line,'\t')

    if db_entry[DB_type]==DB_TYPE_VAL:

      exp_time = time.mktime(dbtime2tuple(db_entry[DB_exp_date]))

      if exp_time < gmt+db_expiretreshold:
        if db_write:
	  db_entry[DB_type] = DB_TYPE_EXP
	expired_db_entries.append(db_entry)

    if db_write:
      db_new.write('%s\n' % string.join(db_entry,'\t'))

    db_line = string.strip(db_old.readline())

  db_old.close()
  if db_write:
    db_new.close()
  
  return expired_db_entries

class OpenSSLcaDatabaseClass:

  def __init__(self,pathname):
    self.pathname = pathname

  def Expire(self):
    return Expire(self.pathname)

  def ExpireWarning(self,treshold):
    return Expire(self.pathname,db_expiretreshold=treshold,db_write=0)

  def Revoke(self,serial):
    Revoke(self.pathname,serial)

  def GetEntriesbyDN(self,DN=empty_DN_dict,casesensitive=0,onlyvalid=0):
    return GetEntriesbyDN(self.pathname,DN,casesensitive,onlyvalid)

  def GetEntrybySerial(self,serial):
    return GetEntrybySerial(self.pathname,serial)

