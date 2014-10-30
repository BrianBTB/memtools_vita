#!/bin/bash

echo "Extremely simple script made by SMOKE to aid in memtools testing"
git fetch
git checkout debug
git pull origin debug
chmod a+x serv.py
# Starting logfile
script serv.py.log
