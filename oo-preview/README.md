# OOPreview

Simple service that uses [OnlyOffice Document Builder](https://api.onlyoffice.com/docbuilder/basic)
to generate documents previews, with the high compatibility with Microsoft Office formats. Supported
generating the preview for the first or all pages.

Theoretically supported formats: https://api.onlyoffice.com/editors/conversionapi#text-matrix (not all recognized by AL)

Built service includes the OnlyOffice binaries licensed as AGPL, see [OnlyOffice license](https://github.com/ONLYOFFICE/DocumentBuilder/blob/master/LICENSE.txt), and non-free Microsoft fonts installed by  [ttf-mscorefonts-installer](https://packages.debian.org/bookworm/ttf-mscorefonts-installer)