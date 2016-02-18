#!/bin/sh
# release.sh
# build a release tarball

if [ $# -gt 0 ]; then
    VERSION=$1
else
    echo "$0 VERSION"
    exit 1
fi

BASENAME=mod_dosdetector-fork-$VERSION
FILENAME=$BASENAME.tar.gz
FILES="Makefile README.md dosdetector-sample.conf mod_dosdetector.c"

mkdir $BASENAME
cp $FILES $BASENAME/
tar cvzf $FILENAME $BASENAME && rm -rf $BASENAME/


