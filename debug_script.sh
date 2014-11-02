#!/bin/bash

echo "Extremely simple script made by SMOKE to aid in memtools testing"
git pull origin
git fetch
git checkout debug
git pull origin debug

chmod a+x serv.py
# Starting logfile
command 2>&1 | tee ~/serv.py.log && ./serv.py

