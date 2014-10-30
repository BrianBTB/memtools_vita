#!/bin/bash

echo "Extremely simple script made by SMOKE to aid in memtools testing"
echo "Type python serv.py after script finishes, then type exit after closing server to save log"
git fetch
git checkout debug
git pull origin debug
chmod a+x serv.py
# Starting logfile
echo "python serv.py && exit" | script serv.py.log
exit
