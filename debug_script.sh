#!/bin/bash

# Extremely simple script made by SMOKE to aid in memtools testing
git fetch
git checout debug
git pull origin debug
chmod a+x serv.py
# Starting logfile
script serv.py.log