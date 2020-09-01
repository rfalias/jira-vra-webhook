#!/usr/bin/env python

import sys
import site

site.addsitedir('/var/www/flask/lib/python3.6/site-packages')
sys.path.insert(1, '/var/www/flask/app')
sys.path.insert(0, '/var/www/flask')

from app import app as application
