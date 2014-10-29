#!/bin/bash

# Extremely simple script made by SMOKE to aid in memtools testing
git clone https://github.com/BrianBTB/memtools_vita
cd memtools_vita
git pull origin
git fetch
git checkout debug
chmod a+x serv.py
# Starting logfile
script serv.py.log && ./serv.py