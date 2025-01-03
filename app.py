def process_drm(buffer, positions):
    processed_buffer = bytearray(buffer)
    
    for pos in positions:
        # Recherche de la séquence object/stream
        pre_context = buffer[max(0,pos-1000):pos+1000].decode('latin-1', errors='ignore')
        
        # Trouver les points clés
        end_stream_marker = "endstream"
        end_obj_marker = "endobj"
        obj_marker = " 0 obj"
        stream_marker = "stream\n"
        
        # Délimiter la zone à traiter
        end_stream_pos = pre_context.find(end_stream_marker)
        end_obj_pos = pre_context.find(end_obj_marker, end_stream_pos)
        next_obj_pos = pre_context.find(obj_marker, end_obj_pos)
        next_stream_pos = pre_context.find(stream_marker, next_obj_pos)
        
        if all(x != -1 for x in [end_stream_pos, end_obj_pos, next_obj_pos, next_stream_pos]):
            abs_pos = max(0,pos-1000)
            
            st.write(f"Structure trouvée:")
            st.write(f"- endstream: {abs_pos + end_stream_pos}")
            st.write(f"- endobj: {abs_pos + end_obj_pos}")
            st.write(f"- nouvel obj: {abs_pos + next_obj_pos}")
            st.write(f"- stream: {abs_pos + next_stream_pos}")
            
            # 1. Modifier l'en-tête de l'objet
            header_start = abs_pos + next_obj_pos
            header_end = abs_pos + next_stream_pos
            header = pre_context[next_obj_pos:next_stream_pos]
            
            # Modifier FOPN
            filter_pos = header.find('/Filter/FOPN_foweb')
            if filter_pos != -1:
                abs_filter_pos = header_start + filter_pos
                processed_buffer[abs_filter_pos:abs_filter_pos+18] = b'/Filter/FlateDecode'
            
            # Modifier V
            v_pos = header.find('/V 1')
            if v_pos != -1:
                abs_v_pos = header_start + v_pos + 3
                processed_buffer[abs_v_pos] = ord('0')
            
            # 2. Effacer le contenu du stream
            content_start = abs_pos + next_stream_pos + len(stream_marker)
            next_end_stream = pre_context.find(end_stream_marker, next_stream_pos)
            content_end = abs_pos + next_end_stream
            
            st.write(f"Effacement contenu {content_start}-{content_end}")
            dump_buffer(buffer, content_start, min(50, content_end-content_start), "Avant:")
            processed_buffer[content_start:content_end] = b'\x00' * (content_end - content_start)
            dump_buffer(processed_buffer, content_start, min(50, content_end-content_start), "Après:")
    
    return bytes(processed_buffer)import streamlit as st
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

def process_drm(buffer, positions):
    processed_buffer = bytearray(buffer)
    
    for pos in positions:
        # Trouver l'objet PDF
        pre_context = buffer[max(0,pos-1000):pos].decode('latin-1', errors='ignore')
        obj_marker = pre_context.rfind(' 0 obj')
        if obj_marker != -1:
            obj_num_start = pre_context.rfind('\n', 0, obj_marker)
            if obj_num_start != -1:
                obj_id = pre_context[obj_num_start:obj_marker].strip()
                st.write(f"Traitement de l'objet: {obj_id}")
            
            abs_obj_start = max(0,pos-1000) + obj_marker
            st.write(f"Début obj: {abs_obj_start}")
            dump_buffer(buffer, abs_obj_start, 50, "Header objet:")
                
        # Chercher séquence stream/endstream
        context = buffer[pos-100:pos+1000].decode('latin-1', errors='ignore')
        stream_pos = context.find('stream\n')
        endstream_pos = context.find('endstream')
        
        if stream_pos != -1 and endstream_pos != -1:
            abs_stream_start = (pos-100) + stream_pos + 7
            abs_stream_end = (pos-100) + endstream_pos
            st.write(f"Stream: {abs_stream_start}-{abs_stream_end}")
            
            # Corriger l'en-tête
            filter_pos = context.find('/Filter/FOPN_foweb')
            if filter_pos != -1:
                abs_filter_pos = (pos-100) + filter_pos
                st.write(f"Remplacement filtre: {abs_filter_pos}")
                processed_buffer[abs_filter_pos:abs_filter_pos+18] = b'/Filter/FlateDecode'
                
            v_pos = context.find('/V 1')
            if v_pos != -1:
                abs_v_pos = (pos-100) + v_pos + 3
                st.write(f"Modification V: {abs_v_pos}")
                processed_buffer[abs_v_pos] = ord('0')
            
            # Effacer contenu chiffré
            st.write(f"Effacement contenu: {abs_stream_start}-{abs_stream_end}")
            processed_buffer[abs_stream_start:abs_stream_end] = b'\x00' * (abs_stream_end - abs_stream_start)
    
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
