#!/bin/bash

# 该模块用于枚举所有app
sysappdir=/Applications
storeappdir=/var/containers/Bundle/Application

for appdir in $(ls ${storeappdir}); do 
    echo ${storeappdir}/${appdir}/*.app; 
done

for appdir in $(ls ${sysappdir}); do 
    echo ${storeappdir}/${appdir}; 
done
