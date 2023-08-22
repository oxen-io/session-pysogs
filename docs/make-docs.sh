#!/bin/bash

# The following npm packages must be installed 
# docsify-cli docsify-themeable docsify-katex@1.4.4 katex marked@4

# To customise the theme see:
# https://jhildenbiddle.github.io/docsify-themeable/#/customization

set -e

if [ "$(basename $(pwd))" != "docs" ] || ! [ -e "make-docs.sh" ]; then
    echo "Error: you must run this from the docs directory" >&2
    exit 1
fi

rm -rf api

npx docsify init --local api

rm -Rf api/vendor/themes
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


cp $npm_dir/docsify/lib/plugins/search.min.js api/vendor
cp $npm_dir/prismjs/components/prism-{json,python,http}.min.js api/vendor
cp $npm_dir/docsify-themeable/dist/css/theme-simple.css api/vendor
cp $npm_dir/docsify-themeable/dist/css/theme-simple-dark.css api/vendor
cp $npm_dir/docsify-themeable/dist/js/docsify-themeable.min.js api/vendor
cp $npm_dir/marked/marked.min.js api/vendor
cp $npm_dir/katex/dist/katex.min.js api/vendor
cp $npm_dir/katex/dist/katex.min.css api/vendor
cp -R $npm_dir/katex/dist/fonts api/vendor
cp $npm_dir/docsify-katex/dist/docsify-katex.js api/vendor

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
      themeable: {
        readyTransition : true, // default
        responsiveTables: true  // default
      }
    }
  </script>\n};
    }
} else {
    s{<title>.*</title>}{<title>Session PySOGS API</title>};
    s{(name="description" content=)"[^"]*"}{$1"Session PySOGS API documentation"};
    s{^\s*<link rel="stylesheet" href="vendor/themes/vue.css">\s*$}{};
    if (m{^\s*</body>}) {
        print qq{
  <link rel="stylesheet" href="vendor/katex.min.css" />
  <link rel="stylesheet" media="(prefers-color-scheme: light)" href="vendor/theme-simple.css">
  <link rel="stylesheet" media="(prefers-color-scheme: dark)" href="vendor/theme-simple-dark.css">
  <style>
    :root {
      --content-max-width : 1100px;
    }
  </style>
  <script src="vendor/search.min.js"></script>
  <script src="vendor/prism-json.min.js"></script>
  <script src="vendor/prism-python.min.js"></script>
  <script src="vendor/prism-http.min.js"></script>
  <script src="vendor/marked.min.js"></script>
  <script src="vendor/katex.min.js"></script>
  <script src="vendor/docsify-katex.js"></script>
  <script src="vendor/docsify-themeable.min.js"></script>
};
    }
    print;
}' api/index.html

