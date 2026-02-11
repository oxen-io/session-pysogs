#!/usr/bin/env python3

from sogs.web import app
import inspect
import re
import os
import argparse
import sys
import shutil

parser = argparse.ArgumentParser()
parser.add_argument(
    "-L",
    "--markdown-level",
    type=int,
    choices=[1, 2, 3, 4],
    default=1,
    help="Specify a heading level for the generated markdown; the default is 1, which means the "
    "top-level headings start with a single `#`, sub-headings start with `##`, etc.  For example, "
    "3 would start with `###`, sub-headings would be `####`, etc.",
)
parser.add_argument(
    "-m",
    "--multi-file",
    action="store_true",
    help="Write to one markdown file per section, rather than one single large file",
)
parser.add_argument(
    "-o",
    "--output",
    type=str,
    help="Specify output file (or directory, when using -m); specifying a - or omitting outputs to "
    "stdout, but is not accepted in multi-file (-m) mode.",
)
parser.add_argument(
    "-W",
    "--overwrite",
    action="store_true",
    help="Allowing overwriting `-o` filename if it already exists",
)

args = parser.parse_args()

out_file = False
if args.multi_file and (not args.output or args.output == '-'):
    print("-o must specify a directory when using -m")
    sys.exit(1)

if not args.multi_file and args.output and args.output != '-':
    if not args.overwrite and os.path.exists(args.output):
        print(f"{args.output} already exists; remove it first or use --overwrite/-W to overwrite")
        sys.exit(1)
    out_file = True

h1 = '#' * args.markdown_level
h2 = '#' + h1
h3 = '#' + h2

# Path where we look for extra docs snippets to include for longer content (examples, etc.) that we
# don't want to embed inside the routes/*.py files.  In here we look for:
#
# - xyz.md -- for the main sections by blueprint name, e.g. rooms.md.  These should exist for each
#   blueprint (otherwise we'll just print an empty stub).
#
# - uncategorized.md -- section description for "Other" endpoints (i.e. that don't have a blueprint)
#
# - xyz.abc.md -- for supplemental info for an endpoint to concatenate after the docstring.  xyz is
#   the blueprint name and abc is typically the function name.  For example
#   `legacy.handle_legacy_get_file.md` or `rooms.messages_since.md`.  (Non-blueprinted names, such
#   as `serve_invite_qr`, don't have a `xyz.` prefix).  These are completely optional: if they don't
#   exist we don't add anything.
#
# In both cases subsections should be started with a single '#' -- we will prefix it with additional
# '#' for the current header depth as appropriate.
snippets = os.path.abspath(os.path.dirname(__file__) + '/snippets')


def read_snippet(markdown, depth=args.markdown_level):
    desc = snippets + '/' + markdown
    if os.path.exists(desc):
        with open(desc) as f:
            return re.sub(r'(?m)^#', f'{"#" * depth}', f.read()) + "\n\n"
    return None


section_list, section_names, section_snips, sections = [], [], [], {}
for name, bp in app.blueprints.items():
    s = []
    section_list.append(s)
    section_names.append(name)
    sections[name] = s
    snip = read_snippet(f'{name}.md')
    if snip:
        s.append(snip)
    else:
        s.append(f"{h1} {name.title()}\n\n")
        app.logger.warning(f"{name}.md not found: adding stub '{name.title()}' section")
    section_snips.append(snip)

# Last section is for anything with a not found category:
section_list.append([])
section_names.append('uncategorized')


# Sort endpoints within a section by the number of URL parts, first, then alphabetically because we
# almost always want the more general, shorter endpoints earlier.
def endpoint_sort_key(rule):
    return (rule.rule.count('/'), rule.rule)


for rule in sorted(app.url_map.iter_rules(), key=endpoint_sort_key):
    ep = rule.endpoint
    if ep == 'static':
        continue
    methods = [m for m in rule.methods if m not in ('OPTIONS', 'HEAD')]
    if not methods:
        app.logger.warning(f"Endpoint {ep} has no useful method, skipping!")
        continue
    method = methods[0]
    if len(methods) > 1:
        app.logger.warning(
            f"Endpoint {ep} ({rule.rule}) has unexpected multiple methods: {methods}"
            f"; using {method}"
        )

    handler = app.view_functions[ep]

    doc = handler.__doc__
    if ep.startswith('legacy'):
        # We deliberately omit legacy endpoint documentation
        if doc is not None:
            app.logger.warning(f"Legacy endpoint {ep} has docstring but it will be omitted")
        continue
    if doc is None:
        app.logger.warning(f"Endpoint {ep} has no docstring!")
        doc = '*(undocumented)*'
    else:
        doc = inspect.cleandoc(handler.__doc__)

    # Update header indent to whatever it should be given the nesting that is applied
    doc = re.sub(r'(?m)^#', h3, doc)

    # url = re.sub(r'<[\w.]+:(\w+)>', r'❮\1❯', rule.rule)
    url = re.sub(r'<[\w.]+:(\w+)>', r'*⟪\1⟫*', rule.rule)

    blueprint, dot, name = ep.partition('.')
    if dot and blueprint in sections:
        s = sections[blueprint]
    else:
        s = section_list[-1]

    s.append(f"{h2} {method} {url}\n\n")

    # If we find a URL Parameters heading already in the doc string then we just add the parameters
    # under it:
    pre, params, doc = doc.partition(f'\n{h3} URL Parameters\n')
    if not rule._converters:
        if params:
            s.append("\nNone.\n\n")
        else:
            s.append(pre)

    else:
        if params:
            s.append(pre)
        else:
            # Otherwise we look for a heading starting with `Return` (e.g. Return values) and, if
            # found, put it before that:
            retpos = pre.find(f'\n{h3} Return')
            if retpos != -1:
                s.append(pre[:retpos])
                doc = pre[retpos:]
            else:
                # Otherwise we'll just stick it at the end
                s.append(pre)

        s.append(f'\n\n{h3} URL Parameters\n\n')
        for arg in sorted(rule._converters.keys(), key=lambda arg: rule.rule.find(f':{arg}>')):
            converter = rule._converters[arg]

            # If we have following doc that already contains this parameter already then skip it, so
            # that you can override parameter descriptions in the docstring.
            if doc and re.search(fr'(?m)^\s*- `{arg}`', doc):
                continue

            s.append(f"- `{arg}`")
            argdoc = converter.__doc__
            if argdoc:
                argdoc = inspect.cleandoc(argdoc)
                # Built-in flask/werkzeug converters are in RST with a '::' at the end of the first
                # line description:
                argdoc = argdoc.partition('::')[0]
                # If we have multiple paragraphs then take just the first one
                argdoc = argdoc.partition('\n\n')[0]

                argdoc = argdoc.replace('\n', '\n  ')

                if ':`' in argdoc:
                    app.logger.warning(
                        f"{method} {url} ({arg}) still contains some rst crap we need to handle"
                    )

                s.append(f" — {argdoc}\n\n")
            else:
                app.logger.warning(
                    f"No documentation found for '{arg}' parameter ({type(converter)})"
                )
                s.append("\n\n")

    if doc:
        s.append(doc)
        s.append("\n\n")

    more = read_snippet(f'{ep}.md', depth=3)
    if more:
        s.append("\n\n")
        s.append(more)

    s.append("\n\n\n")


out = open(args.output, 'w') if out_file else sys.stdout if not args.multi_file else None

if section_list[-1]:
    # We have some uncategorized entries, so load the .md for it
    other = read_snippet('uncategorized.md')
    if not other:
        app.logger.warning(
            "Found uncategorized sections, but uncategorized.md not found; inserting stub"
        )
        other = "# Uncategorized Endpoints\n\n"

    section_list[-1].insert(0, other)
    section_snips.append(other)

else:
    section_list.pop()
    section_names.pop()

if args.multi_file:
    if not os.path.exists(args.output):
        os.makedirs(args.output)
    if not args.overwrite and os.path.exists(args.output + '/index.md'):
        print(f"{args.output}/index.md already exists; remove it first or use --overwrite/-W")
        sys.exit(1)

    api_readme_f = open(args.output + '/index.md', 'w')

section_order = range(0, len(section_list))
if args.multi_file:
    # In multi-file mode we take the order for the index file section from the order it is listed in
    # sidebar.md:
    sidebar = read_snippet('sidebar.md')
    shutil.copy(snippets + '/sidebar.md', args.output + '/sidebar.md')

    def pos(i):
        x = sidebar.find(section_names[i])
        return x if x >= 0 else len(sidebar)

    section_order = sorted(section_order, key=pos)

for i in section_order:
    if args.multi_file:
        filename = args.output + '/' + section_names[i] + '.md'
        if not args.overwrite and os.path.exists(filename):
            print(f"{filename} already exists; remove it first or use --overwrite/-W to overwrite")
            sys.exit(1)
        if out is not None:
            out.close()
        out = open(filename, 'w')

        if section_names[i] + '.md' not in sidebar:
            app.logger.warning(
                f"{section_names[i]}.md not found in snippets/sidebar.md: "
                "section will be missing from the sidebar!"
            )

        snip = section_snips[i]
        if snip.startswith(f'{h1} '):
            preamble = snip.find(f'{h2}')
            if preamble == -1:
                preamble = snip
            else:
                preamble = snip[:preamble]
            print(
                re.sub(fr'^{h1} (.*)', fr'{h1} [\1]({section_names[i]}.md)', preamble),
                file=api_readme_f,
            )
        else:
            app.logger.warning(
                f"{section_names[i]} section didn't start with expected '# Title', "
                f"cannot embed section link in {args.output}/index.md"
            )

    for x in section_list[i]:
        print(x, end='', file=out)
    print("\n\n", file=out)

if out is not None and out != sys.stdout:
    out.close()

app.logger.info("API doc created successfully!")
