#!/bin/bash

stap -e 'probe kernel.function("sys_open") {log("hello world") exit()}'