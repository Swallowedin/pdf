import streamlit as st
import io
import logging
from pathlib import Path
import PyPDF2

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def dump_buffer(buffer, start, length, prefix=""):
    hex_dump = ' '.join([f"{b:02x}" for b in buffer[start:start+length]])
    ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in buffer[start:start+length]])
    st.write(f"{prefix} HEX: {hex_dump}")
    st.write(f"{prefix} ASCII: {ascii_dump}")

def find_all_occurrences(text, pattern):
    pos = 0
    while True:
        pos = text.find(pattern, pos)
        if pos == -1: break
        yield pos
        pos += 1

def find_parameter(context, param, abs_pos):
    st.write(f"\n=== Recherche paramètre {param} depuis position {abs_pos} ===")
    try:
        param_forms = [
            {'pattern': f'/{param} ', 'type': 'numérique'},
            {'pattern': f'/{param}(', 'type': 'parenthèses'},
            {'pattern': f'/{param}/', 'type': 'chemin'},
            {'pattern': f'/{param}<<', 'type': 'dictionnaire'}
        ]
        
        for form in param_forms:
            pattern = form['pattern']
            start = context.find(pattern)
            if start != -1:
                st.write(f"Trouvé {pattern} à position relative {start} (absolue: {abs_pos + start})")
                pos = start + len(pattern)
                relative_context = context[max(0, start-10):min(len(context), start+50)]
                st.write(f"Contexte: ...{relative_context}...")
                
                if pattern.endswith('('):
                    end = context.find(')', pos)
                    if end != -1:
                        value = context[pos:end]
                        st.write(f"→ Valeur ({form['type']}): '{value}'")
                        st.write(f"→ Position valeur: {abs_pos + pos}-{abs_pos + end}")
                        return {
                            'value': value,
                            'start': abs_pos + pos,
                            'end': abs_pos + end,
                            'type': form['type']
                        }
                else:
                    value = ''
                    for i, char in enumerate(context[pos:pos+20]):
                        if char in '0123456789.':
                            value += char
                        else:
                            break
                    if value:
                        st.write(f"→ Valeur ({form['type']}): '{value}'")
                        st.write(f"→ Position valeur: {abs_pos + pos}-{abs_pos + pos + len(value)}")
                        return {
                            'value': value,
                            'start': abs_pos + pos,
                            'end': abs_pos + pos + len(value),
                            'type': form['type']
                        }
        return None
    
    except Exception as e:
        st.error(f"Erreur lors de la recherche du paramètre {param}: {str(e)}")
        return None

def process_drm(buffer, positions):
    st.write("\n=== DÉBUT TRAITEMENT DRM ===")
    processed_buffer = bytearray(buffer)
    
    for idx, pos in enumerate(positions):
        st.write(f"\n== Traitement occurrence {idx+1}/{len(positions)} à position {pos} ==")
        context_start = max(0, pos - 50)
        context = buffer[context_start:context_start+1000].decode('latin-1', errors='ignore')
        
        st.write("\nAnalyse structure PDF:")
        dump_buffer(buffer, context_start, min(200, len(context)), "Structure:")
        
        # 1. Replace FOPN_foweb filter
        filter_pos = context.find('/Filter/FOPN_foweb')
        if filter_pos != -1:
            abs_filter_pos = context_start + filter_pos
            st.write(f"\nRemplacement filtre à position {abs_filter_pos}:")
            dump_buffer(processed_buffer, abs_filter_pos, 18, "Avant:")
            replacement = b'/Filter/FlateDecode'
            for i, byte in enumerate(replacement):
                processed_buffer[abs_filter_pos + i] = byte
            dump_buffer(processed_buffer, abs_filter_pos, 18, "Après:")
        
        # 2. Set V parameter to 0
        v_pos = context.find('/V 1')
        if v_pos != -1:
            abs_v_pos = context_start + v_pos + 3
            st.write(f"\nModification V à position {abs_v_pos}:")
            dump_buffer(processed_buffer, abs_v_pos, 1, "Avant:")
            processed_buffer[abs_v_pos] = ord('0')
            dump_buffer(processed_buffer, abs_v_pos, 1, "Après:")
        
        # 3. Handle encrypted content
        info_pos = context.find('/INFO(')
        if info_pos != -1:
            info_start = context_start + info_pos + 6
            info_len = 40  # Fixed length from Length parameter
            st.write(f"\nEffacement contenu chiffré {info_start}-{info_start+info_len}:")
            dump_buffer(processed_buffer, info_start, info_len, "Avant:")
            processed_buffer[info_start:info_start+info_len] = b'\x00' * info_len
            dump_buffer(processed_buffer, info_start, info_len, "Après:")
        
        # 4. Handle stream markers
        endstream_pos = context.find('endstream', info_pos if info_pos != -1 else 0)
        if endstream_pos != -1:
            abs_end = context_start + endstream_pos
            st.write(f"Marqueur endstream trouvé: {abs_end}")
            
            # Look for stream begin
            stream_pos = context.rfind('stream', 0, endstream_pos)
            if stream_pos != -1:
                abs_stream = context_start + stream_pos
                st.write(f"Marqueur stream trouvé: {abs_stream}")
                # Clear content between markers
                st.write(f"Nettoyage contenu entre markers: {abs_stream+7}-{abs_end}")
                processed_buffer[abs_stream+7:abs_end] = b'\x00' * (abs_end - (abs_stream+7))
    
    st.write("\n=== FIN TRAITEMENT DRM ===")
    return bytes(processed_buffer)

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
    try:
        st.write("=== DÉBUT ANALYSE PDF ===")
        st.write(f"Taille du fichier: {len(file_bytes)} bytes")
        st.write(f"Signature: {file_bytes[:8].hex()}")
        
        if file_bytes[:4] != b'%PDF':
            raise ValueError("Format invalide - Pas un PDF")
        
        content_latin = file_bytes.decode('latin-1', errors='ignore')
        matches = list(find_all_occurrences(content_latin, '/FOPN_foweb'))
        if matches:
            st.write("\n=== OCCURRENCES PROTECTION FILEOPEN ===")
            for i, pos in enumerate(matches):
                st.write(f"\n== Occurrence {i+1}/{len(matches)} ==")
                st.write(f"Position: {pos}")
                context_start = max(0, pos - 50)
                context = content_latin[context_start:pos + 200]
                st.write(f"Contexte: {context}")
                dump_buffer(file_bytes, context_start, min(200, len(context)), "Premier bloc:")
            
            st.write("\n=== DÉPROTECTION DRM ===")
            processed_buffer = process_drm(file_bytes, matches)
            extracted_text = extract_text_from_pdf(processed_buffer)
            
            drm_info = {
                'has_fileopen': True,
                'type': 'FileOpen DRM',
                'filter': 'FOPN_foweb',
                'key_length': '5 bytes',
                'file_size': len(file_bytes),
                'size_kb': round(len(file_bytes) / 1024)
            }
        else:
            st.write("Pas de protection FileOpen détectée")
            processed_buffer = file_bytes
            extracted_text = extract_text_from_pdf(file_bytes)
            
            drm_info = {
                'has_fileopen': False,
                'type': 'Pas de DRM FileOpen',
                'filter': 'N/A',
                'key_length': 'N/A',
                'file_size': len(file_bytes),
                'size_kb': round(len(file_bytes) / 1024)
            }
        
        return drm_info, processed_buffer, extracted_text
        
    except Exception as e:
        st.error(f"Erreur analyse PDF: {str(e)}")
        raise

def main():
    st.set_page_config(page_title="Analyse DRM FileOpen", layout="wide")
    st.title("Analyse DRM FileOpen")
    
    uploaded_files = st.file_uploader("Déposez vos PDF ici", type=['pdf'], accept_multiple_files=True)
    
    if uploaded_files:
        for uploaded_file in uploaded_files:
            try:
                st.write(f"\n=== TRAITEMENT {uploaded_file.name} ===")
                file_bytes = uploaded_file.getvalue()
                
                drm_info, processed_buffer, extracted_text = analyze_pdf(file_bytes)
                
                st.header(f"Résultats pour {uploaded_file.name}")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Type de protection", drm_info['type'])
                    st.metric("Filtre", drm_info['filter'])
                with col2:
                    st.metric("Taille de la clé", drm_info['key_length'])
                    st.metric("Taille du fichier", f"{drm_info['size_kb']} KB")
                
                if drm_info['has_fileopen']:
                    st.warning("Protection FileOpen détectée et déprotégée")
                    
                    if extracted_text:
                        with st.expander("Voir texte extrait"):
                            st.text_area("Contenu", extracted_text, height=200)
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.download_button(
                                "📄 Télécharger texte",
                                extracted_text,
                                file_name=f"{uploaded_file.name}_text.txt",
                                mime="text/plain"
                            )
                        with col2:
                            st.download_button(
                                "📄 Télécharger PDF déprotégé",
                                processed_buffer,
                                file_name=f"{uploaded_file.name}_unprotected.pdf",
                                mime="application/pdf"
                            )
            
            except Exception as e:
                st.error(f"❌ Erreur lors du traitement de {uploaded_file.name}: {str(e)}")
                continue

if __name__ == "__main__":
    main()
