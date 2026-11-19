import os
import zipfile
import xml.sax.saxutils as saxutils

def escape(text):
    return saxutils.escape(str(text))

def create_docx(file_path, title, paragraphs):
    """Génère un fichier Word .docx valide conforme au standard OpenXML (ISO/IEC 29500)."""
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""

    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

    doc_body = []
    # Title
    doc_body.append(f"""<w:p>
      <w:pPr>
        <w:pStyle w:val="Title"/>
        <w:jc w:val="center"/>
      </w:pPr>
      <w:r>
        <w:rPr>
          <w:b/>
          <w:sz w:val="52"/>
          <w:color w:val="0F172A"/>
          <w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/>
        </w:rPr>
        <w:t>{escape(title)}</w:t>
      </w:r>
    </w:p>""")

    for p in paragraphs:
        if p.startswith("# "):
            doc_body.append(f"""<w:p>
              <w:pPr><w:pStyle w:val="Heading1"/><w:spacing w:before="240" w:after="120"/></w:pPr>
              <w:r><w:rPr><w:b/><w:sz w:val="36"/><w:color w:val="0284C7"/><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/></w:rPr><w:t>{escape(p[2:])}</w:t></w:r>
            </w:p>""")
        elif p.startswith("## "):
            doc_body.append(f"""<w:p>
              <w:pPr><w:pStyle w:val="Heading2"/><w:spacing w:before="180" w:after="80"/></w:pPr>
              <w:r><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="0369A1"/><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/></w:rPr><w:t>{escape(p[3:])}</w:t></w:r>
            </w:p>""")
        elif p.startswith("- "):
            doc_body.append(f"""<w:p>
              <w:pPr><w:ind w:left="400"/><w:spacing w:after="60"/></w:pPr>
              <w:r><w:rPr><w:sz w:val="22"/><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/></w:rPr><w:t>• {escape(p[2:])}</w:t></w:r>
            </w:p>""")
        else:
            doc_body.append(f"""<w:p>
              <w:pPr><w:spacing w:after="120"/></w:pPr>
              <w:r><w:rPr><w:sz w:val="22"/><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI"/></w:rPr><w:t>{escape(p)}</w:t></w:r>
            </w:p>""")

    document_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    {"".join(doc_body)}
  </w:body>
</w:document>"""

    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with zipfile.ZipFile(file_path, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml', content_types)
        z.writestr('_rels/.rels', rels)
        z.writestr('word/document.xml', document_xml)

def create_xlsx(file_path, sheet_name, headers, rows):
    """Génère un classeur Excel .xlsx valide conforme au standard OpenXML."""
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>"""

    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

    wb_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""

    workbook_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="{escape(sheet_name)}" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>"""

    styles_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1">
    <font><sz val="11"/><name val="Segoe UI"/></font>
  </fonts>
  <fills count="2">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
  </fills>
  <borders count="1">
    <border><left/><right/><top/><bottom/></border>
  </borders>
  <cellStyleXfs count="1">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>
  </cellStyleXfs>
  <cellXfs count="1">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
  </cellXfs>
</styleSheet>"""

    sheet_rows = []
    # Headers
    header_cells = "".join([f'<c t="inlineStr"><is><t>{escape(h)}</t></is></c>' for h in headers])
    sheet_rows.append(f'<row r="1">{header_cells}</row>')

    for row_idx, r in enumerate(rows, start=2):
        row_cells = "".join([f'<c t="inlineStr"><is><t>{escape(val)}</t></is></c>' for val in r])
        sheet_rows.append(f'<row r="{row_idx}">{row_cells}</row>')

    sheet_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    {"".join(sheet_rows)}
  </sheetData>
</worksheet>"""

    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with zipfile.ZipFile(file_path, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml', content_types)
        z.writestr('_rels/.rels', rels)
        z.writestr('xl/_rels/workbook.xml.rels', wb_rels)
        z.writestr('xl/workbook.xml', workbook_xml)
        z.writestr('xl/styles.xml', styles_xml)
        z.writestr('xl/worksheets/sheet1.xml', sheet_xml)

def create_pptx(file_path, slides):
    """Génère une présentation PowerPoint .pptx valide conforme au standard OpenXML."""
    content_types = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
                     '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
                     '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
                     '<Default Extension="xml" ContentType="application/xml"/>',
                     '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>']

    pres_rels = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
                 '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']

    for i in range(1, len(slides) + 1):
        content_types.append(f'<Override PartName="/ppt/slides/slide{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>')
        pres_rels.append(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide{i}.xml"/>')

    content_types.append('</Types>')
    pres_rels.append('</Relationships>')

    root_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
</Relationships>"""

    pres_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <p:sldIdLst>
    {"".join([f'<p:sldId id="{255 + i}" r:id="rId{i}"/>' for i in range(1, len(slides) + 1)])}
  </p:sldIdLst>
  <p:sldSz cx="12192000" cy="6858000"/>
</p:presentation>"""

    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with zipfile.ZipFile(file_path, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml', "\n".join(content_types))
        z.writestr('_rels/.rels', root_rels)
        z.writestr('ppt/_rels/presentation.xml.rels', "\n".join(pres_rels))
        z.writestr('ppt/presentation.xml', pres_xml)

        for i, (title, bullets) in enumerate(slides, start=1):
            bullet_xml = "".join([f"""<a:p><a:r><a:rPr lang="fr-FR" sz="1800"><a:solidFill><a:srgbClr val="334155"/></a:solidFill></a:rPr><a:t>• {escape(b)}</a:t></a:r></a:p>""" for b in bullets])
            slide_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr/>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="2" name="Title"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="838200" y="500000"/><a:ext cx="10515600" cy="1000000"/></a:xfrm></p:spPr>
        <p:txBody>
          <a:bodyPr/>
          <a:p><a:r><a:rPr lang="fr-FR" sz="3600" b="1"><a:solidFill><a:srgbClr val="0284C7"/></a:solidFill></a:rPr><a:t>{escape(title)}</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="Content"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr/></p:nvSpPr>
        <p:spPr><a:xfrm><a:off x="838200" y="1600000"/><a:ext cx="10515600" cy="4500000"/></a:xfrm></p:spPr>
        <p:txBody>
          <a:bodyPr/>
          {bullet_xml}
        </p:txBody>
      </p:sp>
    </p:spTree>
  </p:cSld>
</p:sld>"""
            z.writestr(f'ppt/slides/slide{i}.xml', slide_xml)

