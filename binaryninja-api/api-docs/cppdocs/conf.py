# -*- coding: utf-8 -*-
#
# Binary Ninja Documentation build configuration file, created by
# sphinx-quickstart on Tue Jun 28 23:02:45 2016.
#
# This file is execfile()d with the current directory set to its
# containing dir.
#
# Note that not all possible configuration values are present in this
# autogenerated file.
#
# All configuration values have a default; values that are commented out
# serve to show the default.

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
import platform
import inspect

apipath = os.path.realpath(os.path.join(os.path.abspath('.'), "..", ".."))

if (platform.system() == "Darwin"):
	bnpath=os.path.join(os.path.abspath('.'), "..", "..", "..", "build", "out", "binaryninja.app", "Contents", "Resources", "python")
else:
	bnpath=os.path.join(os.path.abspath('.'), "..", "..", "..", "build", "out", "python")

if not os.path.exists(bnpath):
	if (platform.system() == "Darwin"):
		bnpath=os.path.join(os.path.abspath('.'), "..", "..", "..", "out", "binaryninja.app", "Contents", "Resources", "python")
	else:
		bnpath=os.path.join(os.path.abspath('.'), "..", "..", "..", "out", "python")

sys.path.insert(0, bnpath)
import binaryninja
binaryninja._init_plugins() #force license check

def setup(app):
	app.add_css_file('css/other.css')
	app.is_parallel_allowed('write')

# -- General configuration ------------------------------------------------

# If your documentation needs a minimal Sphinx version, state it here.
#
# needs_sphinx = '1.0'

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.

extensions = [
	'sphinx.ext.autodoc',
	'sphinx.ext.autosummary',
	'sphinx.ext.intersphinx',
	'sphinx.ext.viewcode',
	'breathe'
]

breathe_projects = { "bncpp": "./xml/" }
breathe_default_project = "bncpp"

# Tell sphinx what the primary language being documented is.
primary_domain = 'cpp'

# Tell sphinx what the pygments highlight language should be.
highlight_language = 'cpp'


# General information about the project.
project = u'Binary Ninja C++ API'
copyright = u'2015-2024, Vector 35 Inc'
author = u'Vector 35 Inc'

# The version info for the project you're documenting, acts as replacement for
# |version| and |release|, also used in various other places throughout the
# built documents.
#
# The short X.Y version.
version = u'.'.join(str(binaryninja.core_version()).split('.')[0:2])
release = str(binaryninja.core_version())

language = 'en'

exclude_patterns = []

add_function_parentheses = False

# If true, the current module name will be prepended to all description
# unit titles (such as .. function::).
#
add_module_names = False


# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'trac'

# A list of ignored prefixes for module index sorting.
# modindex_common_prefix = []

# If true, keep warnings as "system message" paragraphs in the built documents.
# keep_warnings = False

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = False


# -- Options for HTML output ----------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd'
html_theme_path = [os.path.join(os.path.abspath("."), "..", "..")]

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
#
html_theme_options = {
	'display_version': True,
	'style_external_links': True,
	'titles_only': True
}

# Add any paths that contain custom themes here, relative to this directory.
# html_theme_path = []

# The name for this set of Sphinx documents.
# "<project> v<release> documentation" by default.
#
html_title = u'Binary Ninja C++ API Documentation v' + version

# A shorter title for the navigation bar.  Default is the same as html_title.
#
html_short_title = u'BN C++ API'

# The name of an image file (relative to this directory) to place at the top
# of the sidebar.
#
# html_logo = None

# The name of an image file (relative to this directory) to use as a favicon of
# the docs.  This file should be a Windows icon file (.ico) being 16x16 or 32x32
# pixels large.
#
html_favicon = u'../../docs/img/favicon.ico'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# Add any extra paths that contain custom files (such as robots.txt or
# .htaccess) here, relative to this directory. These files are copied
# directly to the root of the documentation.
#
# html_extra_path = []

# If not None, a 'Last updated on:' timestamp is inserted at every page
# bottom, using the given strftime format.
# The empty string is equivalent to '%b %d, %Y'.
#
# html_last_updated_fmt = None

# If true, SmartyPants will be used to convert quotes and dashes to
# typographically correct entities.
#
# html_use_smartypants = True

# Custom sidebar templates, maps document names to template names.
#
# html_sidebars = {}

# Additional templates that should be rendered to pages, maps page names to
# template names.
#
# html_additional_pages = {}

# If false, no module index is generated.
#
html_domain_indices = True

# If false, no index is generated.
#
# html_use_index = True

# If true, the index is split into individual pages for each letter.
#
html_split_index = False

# If true, links to the reST sources are added to the pages.
#
html_show_sourcelink = True

# If true, "Created using Sphinx" is shown in the HTML footer. Default is True.
#
html_show_sphinx = False

# If true, "(C) Copyright ..." is shown in the HTML footer. Default is True.
#
# html_show_copyright = True

# If true, an OpenSearch description file will be output, and all pages will
# contain a <link> tag referring to it.  The value of this option must be the
# base URL from which the finished HTML is served.
#
# html_use_opensearch = ''

# This is the file name suffix for HTML files (e.g. ".xhtml").
# html_file_suffix = None

# Language to be used for generating the HTML full-text search index.
# Sphinx supports the following languages:
#   'da', 'de', 'en', 'es', 'fi', 'fr', 'hu', 'it', 'ja'
#   'nl', 'no', 'pt', 'ro', 'ru', 'sv', 'tr', 'zh'
#
# html_search_language = 'en'

# A dictionary with options for the search language support, empty by default.
# 'ja' uses this config value.
# 'zh' user can custom change `jieba` dictionary path.
#
# html_search_options = {'type': 'default'}

# The name of a javascript file (relative to the configuration directory) that
# implements a search results scorer. If empty, the default will be used.
#
# html_search_scorer = 'scorer.js'

# Output file base name for HTML help builder.
htmlhelp_basename = 'BinaryNinjaAPIDocumentation'
