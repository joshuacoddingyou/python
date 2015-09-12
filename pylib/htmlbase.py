# Parameter fuers <BODY>-Tag
bodyPARAM=''

import os, string

def PrintHeading(Msg,Type=1):
  print '<h%d>%s</h%d>' % (Type,Msg,Type)

def PrintHeader(TitleMsg,HTTP_charset='iso-8859-1'):
  print """Content-type: text/html;charset=%s
pragma: no-cache

<html>
<head>
  <title>%s</title>
  <meta name="generator" content="pyCA, see www.pyca.de"/>
</head>
<body %s>
""" % (HTTP_charset,TitleMsg,bodyPARAM)
  return

def PrintFooter():
  print """
  <p align=center>
    <font size=-2>
      Powered by
      <a href="http://www.joshuacoddingyou.com.br/">Josh</a>
    </font>
  </p>
</body>
</html>
"""
  return

def PrintErrorMsg(Msg):
  PrintHeader('Error')
  print """<H1>Error</H1>
%s<P>
""" % (Msg)
  server_admin = os.environ.get('SERVER_ADMIN','')
  if server_admin:
    print 'Please contact <A HREF="mailto:%s">%s</A>.' % (
      server_admin,server_admin
    )
  PrintFooter()
  return

