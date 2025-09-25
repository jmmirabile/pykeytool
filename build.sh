#!/bin/bash
# build.sh - Build all of the PyKeyTool platform executables

for spec in *.spec; do
    echo "Building $spec..."
    pyinstaller $spec || echo "Failed: $spec"
done

echo "Build complete! Files in dist/"