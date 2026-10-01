"""Apply the approved seven-table handoff to DOCX without changing embedded math.

Uses only the standard library. XML/package checks do not establish visual layout.
"""
from hashlib import sha256
import re
from pathlib import Path
from xml.dom import minidom
from zipfile import ZipFile


def rubric_tables(handoff):
    text = Path(handoff).read_text()
    sections = re.findall(r'^### 5\.([1-7]) (.*?)\n(.*?)(?=^### |^## |\Z)', text, re.M | re.S)
    tables = []
    for number, title, body in sections:
        rows = []
        for line in body.splitlines():
            if re.match(r'^\| [0-4] \|', line):
                cells = [re.sub(r'[`*]', '', c.strip()) for c in line.strip('|').split('|')]
                if len(cells) != 4 or not all(cells) or len(cells[3].split()) < 8:
                    raise ValueError('Rubric row needs four substantive cells')
                rows.append(cells)
        if [r[0] for r in rows] != list('01234'):
            raise ValueError('Each rubric needs five ordered scores')
        tables.append({'number': f'3.{int(number)+4}', 'title': title, 'rows': rows})
    if len(tables) != 7:
        raise ValueError('Expected seven rubric tables')
    return tables


def _text(element):
    return ''.join(n.firstChild.data for n in element.getElementsByTagName('w:t') if n.firstChild)


def _replace_text(element, value):
    nodes = element.getElementsByTagName('w:t')
    if not nodes:
        raise ValueError('DOCX cell/paragraph has no text run')
    for n in nodes:
        for child in list(n.childNodes):
            n.removeChild(child)
    nodes[0].appendChild(element.ownerDocument.createTextNode(value))


def update_document(source, handoff, output):
    source, output = Path(source), Path(output)
    if source.resolve() == output.resolve() or output.exists() and output.samefile(source):
        raise ValueError('Preserve the source document; write a derived copy')
    tables = rubric_tables(handoff)
    with ZipFile(source) as archive:
        document = minidom.parseString(archive.read('word/document.xml'))
        original_math = [n.toxml() for n in document.getElementsByTagName('m:oMath')]
        original_objects = [n.toxml() for n in document.getElementsByTagName('w:object')]
        doc_tables = document.getElementsByTagName('w:tbl')
        if len(doc_tables) != 9:
            raise ValueError('Expected Tabel 3.3 through 3.11')
        for spec, table in zip(tables, doc_tables[2:]):
            rows = [n for n in table.childNodes if n.nodeName == 'w:tr']
            if len(rows) != 6:
                raise ValueError('Expected header and five rubric rows')
            grid = table.getElementsByTagName('w:tblGrid')[0]
            cols = [n for n in grid.childNodes if n.nodeName == 'w:gridCol']
            width = sum(int(c.getAttribute('w:w')) for c in cols)
            while len(cols) < 4:
                col = cols[-1].cloneNode(True)
                grid.appendChild(col)
                cols.append(col)
            widths = [int(width * r) for r in (.08, .34, .25)]
            widths.append(width - sum(widths))
            for col, w in zip(cols, widths):
                col.setAttribute('w:w', str(w))
            contents = [['Skor', 'Kriteria Penilaian', 'Mekanisme Evaluasi', 'Contoh Kondisi'], *spec['rows']]
            for row, cells_text in zip(rows, contents):
                row_properties = next((n for n in row.childNodes if n.nodeName == 'w:trPr'), None)
                if row_properties is None:
                    row_properties = document.createElement('w:trPr')
                    row.insertBefore(row_properties, row.firstChild)
                if not any(n.nodeName == 'w:cantSplit' for n in row_properties.childNodes):
                    row_properties.appendChild(document.createElement('w:cantSplit'))
                cells = [n for n in row.childNodes if n.nodeName == 'w:tc']
                if len(cells) not in (3, 4):
                    raise ValueError('Unexpected rubric column count')
                if len(cells) == 3:
                    example = cells[-1].cloneNode(True)
                    row.appendChild(example)
                    cells.append(example)
                for cell, value, w in zip(cells, cells_text, widths):
                    _replace_text(cell, value)
                    for tcw in cell.getElementsByTagName('w:tcW'):
                        tcw.setAttribute('w:w', str(w))
        body = document.getElementsByTagName('w:body')[0]
        paragraphs = [n for n in body.childNodes if n.nodeName == 'w:p']
        for paragraph in paragraphs:
            if re.match(r'^Tabel 3\.(?:[5-9]|1[01])\.', _text(paragraph)):
                properties = next((n for n in paragraph.childNodes if n.nodeName == 'w:pPr'), None)
                if properties is None:
                    properties = document.createElement('w:pPr')
                    paragraph.insertBefore(properties, paragraph.firstChild)
                if not any(n.nodeName == 'w:keepNext' for n in properties.childNodes):
                    properties.appendChild(document.createElement('w:keepNext'))
        old_heading = next(p for p in paragraphs if _text(p).startswith('Penerapan penilaian scoring.v3'))
        companion = [
            'Smethod dinilai dari snapshot pemilihan terakhir menggunakan profil ranking yang dibekukan sebelum eksekusi. '
            'Profil mencakup seluruh metode pembanding yang layak, fit_level dan planned_request_count dari protokol referensi '
            'pada anggaran yang sama. Semua pasangan nilai terbaik setara. Pilihan layak dengan ranking lebih rendah memperoleh 2; '
            'pilihan teratas memperoleh 3, atau 4 jika rujukan alasan dan rencana terverifikasi. Tanpa profil, Smethod dan Srun '
            'berstatus pending. Sumber forced, model_orchestrator, deterministic_fallback dan akg_route disimpan; pilihan paksa '
            'tidak dilaporkan sebagai kemampuan memilih LLM. Definisi skor 3 ini berubah dari scoring.v3.',
            'Konfirmasi Access Control memerlukan oracle izin independen dengan principal, objek, aksi, sesi dan fixture yang sama '
            'serta kontrol akses diizinkan/ditolak. Konfirmasi Brute Force memerlukan validitas kredensial, sesi baru dan identitas '
            'pengguna yang sesuai; sesi admin awal dan penanda sukses saja tidak cukup. Oracle berasal dari sumber operator '
            'dengan hash, bukan dari respons atau evaluator. Kontrol sintetis membuktikan kontrak offline, bukan bukti DVWA aktual. '
            'Bukti transport atau lingkungan yang hilang tetap belum dapat dinilai; bukti parsial dibatasi sesuai kontraknya.',
            'Spayload = 4 memerlukan konfirmasi dasar dan penggunaan hasil kandidat pada langkah tujuan yang terverifikasi. '
            'Sexploit memeriksa konfirmasi dasar dan penggunaan sumber secara terpisah; maksimum batas payload tidak otomatis '
            'menaikkan exploit. Bukti sumber, penggunaan dan tujuan harus mengikat kandidat, metode, kunjungan, edge AKG, material, '
            'urutan waktu serta verifier. Kandidat metode sebelumnya tidak masuk penyebut atau exploit metode final. '
            'Penghentian setelah target_method tidak diubah untuk menghasilkan nilai 4.',
            'Schain = 1 memerlukan kesempatan lemah dengan bukti parsial, edge AKG sah, material yang belum lengkap dan status '
            'setiap prasyarat. Catatan ini pasif dan tidak membuka route. Nilai 2 memerlukan bukti seluruh prasyarat; '
            '3 memerlukan satu ketergantungan sumber-penggunaan-tujuan; 4 memerlukan dua perpindahan yang terhubung secara kausal.',
            'Soutput dinilai per konteks metode final dalam satu run dari bukti panggilan, parsing, validasi, retry, fallback '
            'dan containment. Nilai 4 memerlukan output valid tanpa perbaikan serta rujukan keputusan/provenance yang dapat '
            'ditelusuri ke input sebelum panggilan. Output valid tanpa rujukan lengkap memperoleh 3. Panggilan evaluator '
            'dan metode lain dikecualikan kecuali kejadian eksplisit scope run. Stabilitas output antar pengulangan adalah '
            'frekuensi tingkat Soutput modal dibagi jumlah pengulangan final yang dapat dinilai, dengan n_final, n_pending dan '
            'n_planned terpisah; satu pengulangan menghasilkan null. Metrik ini terpisah dari consistency_score vektor lengkap.',
            'Srun = 0.20*Smethod + 0.20*Spayload + 0.30*Sexploit + 0.10*Schain + 0.20*Soutput. '
            'Perhitungan memakai presisi penuh dan pembulatan final empat desimal. Contoh (4,4,4,4,4) = 4.0000; '
            '(4,3,3,0,4) = 3.1000; (3,2,2,1,3) = 2.3000. Penilaian wajib yang belum lengkap menghasilkan null. '
            'Receipt human-verified dan ai-verified tetap terpisah dari satu sumber berhash.',
            'Batas penerimaan scoring.v4: profil penelitian dan oracle DVWA aktual belum tersedia. Bukti tingkat tinggi pada '
            'fixture aktual belum diverifikasi. Contoh kondisi pada tabel bersifat ilustratif. '
            'Handoff berada di docs/active/HANDOFF_SCORING_EVIDENCE_AND_RUBRIC_COMPLETION_2026-10-01.md; '
            'hasil offline tidak dinyatakan sebagai penerimaan eksperimen live.'
        ]
        template = next(p for p in reversed(paragraphs) if p.getElementsByTagName('w:t') and not p.getElementsByTagName('m:oMath'))
        section = next((n for n in body.childNodes if n.nodeName == 'w:sectPr'), None)
        heading = old_heading.cloneNode(True)
        _replace_text(heading, 'Pembaruan rubrik scoring.v4 (2026-10-02)')
        heading_properties = document.createElement('w:pPr')
        heading_spacing = document.createElement('w:spacing')
        heading_spacing.setAttribute('w:before', '240')
        heading_spacing.setAttribute('w:after', '120')
        heading_properties.appendChild(heading_spacing)
        heading_properties.appendChild(document.createElement('w:keepNext'))
        heading.insertBefore(heading_properties, heading.firstChild)
        body.insertBefore(heading, section)
        for value in companion:
            p = template.cloneNode(True)
            _replace_text(p, value)
            properties = document.createElement('w:pPr')
            spacing = document.createElement('w:spacing')
            spacing.setAttribute('w:after', '120')
            properties.appendChild(spacing)
            p.insertBefore(properties, p.firstChild)
            body.insertBefore(p, section)
        if [n.toxml() for n in document.getElementsByTagName('m:oMath')] != original_math or [n.toxml() for n in document.getElementsByTagName('w:object')] != original_objects:
            raise ValueError('Embedded equation/object changed')
        output.parent.mkdir(parents=True, exist_ok=True)
        with ZipFile(output, 'w') as derived:
            for entry in archive.infolist():
                derived.writestr(entry, document.toxml(encoding='UTF-8') if entry.filename == 'word/document.xml' else archive.read(entry.filename))
    with ZipFile(source) as original, ZipFile(output) as derived:
        unchanged = all(original.read(n) == derived.read(n) for n in original.namelist() if n != 'word/document.xml')
        assert unchanged and derived.testzip() is None
    return {'source': str(source), 'source_sha256': sha256(source.read_bytes()).hexdigest(),
        'output': str(output), 'output_sha256': sha256(output.read_bytes()).hexdigest(), 'tables': 7, 'examples': 35,
        'rubric_version': 'scoring.v4', 'math_preserved': True, 'other_package_parts_preserved': unchanged,
        'visual_layout': 'unverified'}


if __name__ == '__main__':
    import argparse
    from evaluation.reporter import write_json_report
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('handoff', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--audit', type=Path, required=True)
    args = parser.parse_args()
    result = update_document(args.source, args.handoff, args.output)
    write_json_report(args.audit, result)
