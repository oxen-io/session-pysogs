#!/bin/bash

set -e

if [ "$(basename $(pwd))" != "docs" ] || ! [ -e "make-docs.sh" ]; then
    echo "Error: you must run this from the docs directory" >&2
    exit 1
fi

rm -rf api

docsify init --local api

rm -f api/README.md

if [ -n "$NPM_PACKAGES" ]; then
    npm_dir="$NPM_PACKAGES/lib/node_modules"
elif [ -n "$NODE_PATH" ]; then
    npm_dir="$NODE_PATH"
elif [ -d "$HOME/node_modules" ]; then
    npm_dir="$HOME/node_modules"
elif [ -d "/usr/local/lib/node_modules" ]; then
    npm_dir="/usr/local/lib/node_modules"
else
    echo "Can't determine your node_modules path; set NPM_PACKAGES or NODE_PATH appropriately" >&2
    exit 1
fi

cp $npm_dir/docsify/node_modules/prismjs/components/prism-{json,python,http}.min.js api/vendor
cp $npm_dir/docsify-katex/dist/docsify-katex.js api/vendor
cp $npm_dir/docsify-katex/node_modules/katex/dist/katex.min.css api/vendor

PYTHONPATH=.. ./generate-api-docs.py -m -o api

perl -ni.bak -e '
BEGIN { $first = 0; }
if (m{^\s*<script>\s*$} .. m{^\s*</script>\s*$}) {
    if (not $first) {
        $first = false;
        print qq{
  <script>
    window.\$docsify = {
      name: "Session PySOGS API",
      repo: "https://github.com/oxen-io/session-pysogs",
      loadSidebar: "sidebar.md",
      subMaxLevel: 2,
      homepage: "index.md",
    }
  </script>\n};
    }
} else {
    s{<title>.*</title>}{<title>Session PySOGS API</title>};
    s{(name="description" content=)"[^"]*"}{$1"Session PySOGS API documentation"};
    if (m{^\s*</body>}) {
        print qq{
  <script src="vendor/prism-json.min.js"></script>
  <script src="vendor/prism-python.min.js"></script>
  <script src="vendor/prism-http.min.js"></script>
  <script src="vendor/docsify-katex.js"></script>
  <link rel="stylesheet" href="vendor/katex.min.css" />
};
    }
    print;
}' api/index.html

