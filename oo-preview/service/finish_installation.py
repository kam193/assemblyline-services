# For some reason, the DocumentBuilder is not ready to use
# by the assemblyline user until the first usage by root.

import os
import sys

sys.path.append("/opt/onlyoffice/documentbuilder/")

import docbuilder

builder = docbuilder.CDocBuilder()
builder.OpenFile("/opt/onlyoffice/documentbuilder/empty/new.docx", "")
builder.SaveFile(
    "image",
    "/tmp/thumbnail.png",
    "<m_oThumbnail><format>4</format><aspect>1</aspect><first>true</first><width>1024</width><height>1024</height></m_oThumbnail>",
)
builder.CloseFile()
os.remove("/tmp/thumbnail.png")