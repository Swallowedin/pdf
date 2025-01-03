import streamlit as st
import io
import logging
from pathlib import Path
import PyPDF2

logging.basicConfig(level=logging.DEBUG)

def dump_buffer(buffer, start, length, prefix=""):
    hex_dump = ' '.join([f"{b:02x}" for b in buffer[start:start+length]])
    ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in buffer[start:start+length]])
    st.write(f"{prefix} HEX: {hex_dump}")
    st.write(f"{prefix} ASCII: {ascii_dump}")

def find_all_occurrences(text, pattern):
    pos = 0
    while True:
        pos = text.find(pattern, pos)
        if pos == -1:
            break
        yield pos
        pos += 1

def process_drm(buffer, positions):
    processed = bytearray(buffer)
    for pos in positions:
        # 1. Trouver le bloc FileOpen
        context = buffer[pos:pos+1000].decode('latin-1', errors='ignore')
        
        # 2. Remplacer FOPN par FlateDecode
        processed[pos:pos+18] = b'/Filter/FlateDecode'
        st.write(f"Filtre remplacé à {pos}")
        
        # 3. Changer V=1 en V=0
        v_pos = context.find('/V 1')
        if v_pos != -1:
            v_abs = pos + v_pos + 3
            processed[v_abs] = ord('0')
            st.write(f"V modifié à {v_abs}")
        
        # 4. Remplacer le stream chiffré
        info_pos = context.find('/INFO(')
        if info_pos != -1:
            stream_start = pos + info_pos
            stream_end = stream_start + context[info_pos:].find('endstream')
            st.write(f"Stream effacé: {stream_start}-{stream_end}")
            processed[stream_start:stream_end] = b'\x00' * (stream_end - stream_start)
            
    return bytes(processed)

def extract_text_from_pdf(buffer):
    try:
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(buffer))
        text = []
        for i, page in enumerate(pdf_reader.pages):
            text.append(f"=== Page {i+1} ===\n{page.extract_text()}")
        return '\n\n'.join(text)
    except Exception as e:
        st.error(f"Erreur extraction: {str(e)}")
        return None

def analyze_pdf(file_bytes):
    st.write("=== DÉBUT ANALYSE PDF ===")
    st.write(f"Taille: {len(file_bytes)} bytes")
    st.write(f"Signature: {file_bytes[:8].hex()}")
    
    if file_bytes[:4] != b'%PDF':
        raise ValueError("Format invalide")
    
    content = file_bytes.decode('latin-1', errors='ignore')
    matches = list(find_all_occurrences(content, '/FOPN_foweb'))
    
    if not matches:
        st.write("Pas de protection")
        return {'has_fileopen': False}, file_bytes, extract_text_from_pdf(file_bytes)
    
    st.write(f"\n{len(matches)} protection(s) trouvée(s)")
    for i, pos in enumerate(matches):
        st.write(f"\nOccurrence {i+1} à {pos}")
        context = content[pos:pos+200]
        st.write(f"Contexte: {context}")
        
    processed = process_drm(file_bytes, matches)
    
    return {
        'has_fileopen': True,
        'type': 'FileOpen DRM',
        'filter': 'FOPN_foweb',
        'key_length': '5 bytes',
        'file_size': len(file_bytes),
        'size_kb': round(len(file_bytes) / 1024)
    }, processed, extract_text_from_pdf(processed)

def main():
    st.set_page_config(page_title="DRM FileOpen", layout="wide")
    st.title("DRM FileOpen")
    
    files = st.file_uploader("PDF à traiter", type=['pdf'], accept_multiple_files=True)
    
    for file in files:
        try:
            st.write(f"\n=== {file.name} ===")
            bytes_data = file.getvalue()
            
            info, processed, text = analyze_pdf(bytes_data)
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Protection", info.get('type', 'Aucune'))
                st.metric("Filtre", info.get('filter', 'N/A'))
            with col2:
                st.metric("Clé", info.get('key_length', 'N/A'))
                st.metric("Taille", f"{info.get('size_kb', 0)} KB")
            
            if info['has_fileopen']:
                st.warning("Protection FileOpen détectée et déprotégée")
                
                if text:
                    with st.expander("Texte extrait"):
                        st.text_area("Contenu", text, height=200)
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.download_button("📄 Texte", text,
                            f"{file.name}_text.txt", "text/plain")
                    with col2:
                        st.download_button("📄 PDF déprotégé", processed,
                            f"{file.name}_unprotected.pdf", "application/pdf")
        
        except Exception as e:
            st.error(f"Erreur: {str(e)}")

if __name__ == "__main__":
    main()
