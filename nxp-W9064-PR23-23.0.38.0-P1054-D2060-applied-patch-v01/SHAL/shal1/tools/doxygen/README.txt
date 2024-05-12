** OS support **************************************************************************************
SHAL make system supports Doxygen generation on Linux, CygWin, and Windows, provided that the
Doxygen package is already installed.

** Make targets (for Makefile in shal1 dir) ********************************************************
> make doc
> make doc-all
   Create HTML and (PDF-ready) LaTeX documentation in <SHAL-ROOT-DIR>/shal1/doc directory.

> make doc-clean
   Remove <SHAL-ROOT-DIR>/shal1/doc directory.

> make all
> make clean
   Global all/clean targets that, among others, make doc-all/doc-clean targets respectively as well.

** HTML documentation usage ************************************************************************
With a web browser of choice, open the file <SHAL-ROOT-DIR>/shal1/doc/html/index.html.
<SHAL-ROOT-DIR>/shal1/html directory is a self-contained HTML directory that can be freely, moved,
copied, tarballed and e-mailed, stored on a WEB server, etc, and all that is left to do is pointing
a browser to its index.html file.

** Doxygen usage ***********************************************************************************
Generic Doxygen info       : http://www.stack.nl/~dimitri/doxygen/manual/
Documenting the source code: http://www.stack.nl/~dimitri/doxygen/manual/docblocks.html
Customizing the cfg file   : http://www.stack.nl/~dimitri/doxygen/manual/config.html

The configuration file is stored at <SHAL-ROOT-DIR>/shal1/tools/doxygen/doxygen.cfg (i.e. in the
same directory as this file). Besides the customization instructions available at the last web link
here above, a user-friendly alternative to customize the configuration file is doxywizard:
> doxywizard <SHAL-ROOT-DIR>/shal1/tools/doxygen/doxygen.cfg
In order to use doxywizard, depending on your Linux/CygWin distribution you may need to install a
dedicated package different than the one that provides doxygen tool itself.
