"""MyArk UI search package (S9.1).

Submodules:

- :mod:`myark.ui.search.matcher`        -- five match modes (exact / prefix /
  substring / pinyin / regex) with pypinyin fallback.
- :mod:`myark.ui.search.index_builder`  -- build a cross-module search index
  from every registered R3 module's row data.
- :mod:`myark.ui.search.cmd_palette`    -- Ctrl+P command palette Toplevel.
- :mod:`myark.ui.search.adv_search_panel` -- sidebar advanced-search dialog.

The package is pure-R3 -- no driver IOCTLs, only Python data wrangling --
which fits the S9.1 "quadrant ①" constraint.
"""

from .matcher import MatchMode, match, match_any, pinyin_key
from .index_builder import SearchEntry, build_index
from .cmd_palette import CommandPalette, open_palette
from .adv_search_panel import AdvancedFilter, AdvancedSearchPanel, open_panel

__all__ = [
    "MatchMode",
    "match",
    "match_any",
    "pinyin_key",
    "SearchEntry",
    "build_index",
    "CommandPalette",
    "open_palette",
    "AdvancedFilter",
    "AdvancedSearchPanel",
    "open_panel",
]