#!/bin/bash

docker run -it --rm -v $(pwd):/w -w /w -p 1313:13337 --name blog-builder hugomods/hugo:latest server --disableFastRender --bind 0.0.0.0 -p 13337
