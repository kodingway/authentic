#!/bin/sh

# Get venv site-packages path
DSTDIR=`python -c 'from distutils.sysconfig import get_python_lib; print(get_python_lib())'`

# Get not venv site-packages path
# Remove first path (assuming that is the venv path)
NONPATH=`echo $PATH | sed 's/^[^:]*://'`
SRCDIR=`PATH=$NONPATH python -c 'from distutils.sysconfig import get_python_lib; print(get_python_lib())'`

# Clean up
rm -f $DSTDIR/lasso.*
rm -f $DSTDIR/_lasso.*

# Link
ln -sv $SRCDIR/lasso.py $DSTDIR
ln -sv $SRCDIR/_lasso.* $DSTDIR

exit 0

