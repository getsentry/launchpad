import gc
import objgraph

import json

from io import BytesIO, TextIOWrapper
from pathlib import Path

from launchpad.size.runner import do_size, write_results_as_json


def foo():
  output_file = TextIOWrapper(BytesIO())
  path = Path("tests/_fixtures/ios/HackerNews.xcarchive.zip")
  results = do_size(path)
  write_results_as_json(results, output_file)
  output_file.seek(0)
  size = json.load(output_file)
  assert size["app_info"]["name"] == "HackerNews"


objgraph.show_growth()
foo()
print(objgraph.show_growth())
roots = objgraph.by_type("ObjCSymbolTypeGroup")
objgraph.show_refs(roots[0], refcounts=True, filename='roots.png')
objgraph.show_backrefs(roots[0], max_depth=20, refcounts=True, filename='back.png')

