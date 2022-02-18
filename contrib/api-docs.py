import sogs
from sogs.web import app
import inspect
import re
import os


heading_level = 1  # Make this configurable, for easier nesting inside another doc?

h1 = '#' * heading_level
h2 = '#' + h1
h3 = '#' + h2

print(f"{h1} Session Open Group Server API\n")

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
snippets = os.path.abspath(os.path.dirname(__file__) + '/../docs/snippets/')


def read_snippet(markdown, depth=heading_level):
    desc = snippets + '/' + markdown
    if os.path.exists(desc):
        with open(desc) as f:
            return f.read().replace('\n#', f'\n{"#" * depth}') + "\n\n"
    return None


section_list, sections = [], {}
for name, bp in app.blueprints.items():
    s = []
    section_list.append(s)
    sections[name] = s
    snip = read_snippet(f'{name}.md')
    if snip:
        s.append(snip)
    else:
        s.append(f"{h1} {name.title()}\n\n")
        app.logger.warning(f"{name}.md not found: adding stub '{name.title()}' section")

# Last section is for anything with a not found category:
section_list.append([])


# Sort endpoints within a section by the number of URL parts, first, then alphabetically because we
# almost always want the more general, shorter endpoints earlier.
def endpoint_sort_key(rule):
    return (rule.rule.count('/'), rule.rule)


for rule in sorted(app.url_map.iter_rules(), key=endpoint_sort_key):
    ep = rule.endpoint
    methods = [m for m in rule.methods if m not in ('OPTIONS', 'HEAD')]
    if not methods:
        app.logger.warning(f"Endpoint {ep} has no useful method, skipping!")
        continue
    method = methods[0]
    if len(methods) > 1:
        app.logger.warning(
            f"Endpoint {ep} ({rule.rule}) has unexpected multiple methods: {methods}; using {method}"
        )

    handler = app.view_functions[ep]

    doc = handler.__doc__
    if doc is None:
        app.logger.warning(f"Endpoint {ep} has no docstring!")
        doc = '*(undocumented)*'
    else:
        doc = inspect.cleandoc(handler.__doc__)

    # Update header indent to whatever it should be given the nesting that is applied
    doc.replace('\n#', f'\n{h3}')

    url = re.sub(r'<[\w.]+:(\w+)>', r'❮\1❯', rule.rule)

    blueprint, dot, name = ep.partition('.')
    if dot and blueprint in sections:
        s = sections[blueprint]
    else:
        s = section_list[-1]

    s.append(f"{h2} {method} {url}\n\n")

    # If we find this heading in the doc string then we put the parameters there; otherwise we put
    # them at the end:
    pre, params, doc = doc.partition(f'\n{h3} URL Parameters\n')
    s.append(pre)
    s.append("\n")

    if rule._converters:
        s.append(f'\n{h3} URL Parameters\n\n')
        for arg in sorted(rule._converters.keys(), key=lambda arg: rule.rule.find(f':{arg}>')):
            converter = rule._converters[arg]
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
                    app.logger.warning(f"{arg} still contains some rst crap we need to handle")

                s.append(f" — {argdoc}\n\n")
            else:
                app.logger.warning(
                    f"No documentation found for '{arg}' parameter ({type(converter)})"
                )
                s.append("\n\n")
    elif params:
        s.append("\nNone.\n\n")

    if doc:
        s.append(doc)
        s.append("\n\n")

    more = read_snippet(f'{ep}.md', depth=3)
    if more:
        app.logger.critical(f"wtfwtfwtfwtfwtfwtfwtfwtfwtf, {ep}")
        s.append(more)
    else:
        app.logger.critical(f"WTF, {snippets}{ep}")


    s.append("\n\n\n")


print(section_list[-1])
if section_list[-1]:
    # We have some uncategorized entries, so load the .md for it
    other = read_snippet('uncategorized.md')
    if other:
        section_list[-1].insert(0, other)
    else:
        app.logger.warning(
            "Found uncategorized sections, but uncategorized.md not found; inserting stub"
        )
        section_list[-1].insert(0, "# Uncategorized Endpoints\n\n")

for s in section_list:
    for x in s:
        print(x, end='')
    print("\n\n")
