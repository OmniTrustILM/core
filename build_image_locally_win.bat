@echo off

REM Name of the image to build (including tag)
set IMAGE_NAME=ilm/core:develop-latest
REM Dockerfile path for the main image
set DOCKERFILE_PATH=Dockerfile

REM Maven directory that will be mounted to the container to cache dependencies
REM If not set, the container will download dependencies on every build
REM e.g. C:\Users\username\.m2, make sure to use the correct path for your system
set MAVEN_DIR="C:\Users\%USERNAME%\.m2"
REM true to skip tests, default is false
set SKIP_TESTS=false

CALL hooks/build_win.bat
