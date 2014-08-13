#!/bin/sh

set -x

echo "Give project name (it must match regexp ^[a-z][a-z0-9-]+$ )"
read PROJECT_NAME

if ! echo $PROJECT_NAME | grep -q '^[a-z][a-z0-9-]\+$'; then
    echo "Invalid project name:" $PROJECT_NAME
    exit 1
fi

UPPER_UNDERSCORED=`echo $PROJECT_NAME | tr a-z A-Z | sed 's/-/_/g'`
LOWER_UNDERSCORED=`echo $PROJECT_NAME | sed 's/-/_/g'`
TITLECASE=`echo $PROJECT_NAME | sed 's/-/ /g;s/.*/\L&/; s/[a-z]*/\u&/g'`

echo Project name: $PROJECT_NAME
echo Uppercase underscored: $UPPER_UNDERSCORED
echo Lowercase underscored: $LOWER_UNDERSCORED
echo Titlecase: $TITLECASE

if [ -d .git ]; then
	MV='git mv'
else
	MV=mv
fi

sed -i \
   -e "s/authentic2_plugin_template/$LOWER_UNDERSCORED/g" \
   -e "s/authentic2-plugin-template/$PROJECT_NAME/g" \
   -e "s/A2_TEMPLATE_/A2_$UPPER_UNDERSCORED_/g" \
   -e "s/Authentic2 Plugin Template/$TITLECASE/g" \
   setup.py src/*/*.py README COPYING MANIFEST.in
$MV src/authentic2_plugin_template/static/authentic2_plugin_template \
   src/authentic2_plugin_template/static/$LOWER_UNDERSCORED
$MV src/authentic2_plugin_template/templates/authentic2_plugin_template \
   src/authentic2_plugin_template/templates/$LOWER_UNDERSCORED
$MV src/authentic2_plugin_template src/$LOWER_UNDERSCORED
