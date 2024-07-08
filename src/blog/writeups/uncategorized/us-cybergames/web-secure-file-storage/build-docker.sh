#!/bin/bash
docker rm -f uscg_web_secure_file_storage
docker build --tag=uscg_web_secure_file_storage .
docker run -p 1337:80 --rm --name=uscg_web_secure_file_storage uscg_web_secure_file_storage