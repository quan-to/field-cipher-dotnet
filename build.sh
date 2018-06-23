#!/bin/bash

LIBFILE="FieldCipher/bin/Release/FieldCipher.dll"

mkdir -p build/lib/net45
mkdir -p build/lib/net452

msbuild /p:Configuration=Release
cp "${LIBFILE}" build/lib/net45/
cp "${LIBFILE}" build/lib/net452/
LIBVER=`monodis --assembly "${LIBFILE}" |grep Version | cut -d: -f2 | sed -e 's/^[[:space:]]*//'`
#cd build

echo "Current Version: ${LIBVER%.*}"
sed "s/|{|VERSION|}|/${LIBVER%.*}/g" FieldCipher.nuspec.tpl > FieldCipher.nuspec
nuget pack FieldCipher.nuspec -verbosity detailed

