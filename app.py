import streamlit as st
import io
import logging
from pathlib import Path
import PyPDF2
import re

logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def dump_buffer(buffer, start, length, prefix=""):
    hex_dump = ' '.join([f"{b:02x}" for b in buffer[start:start+length]])
    ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in buffer[start:start+length]])
    st.write(f"{prefix} HEX: {hex_dump}")
    st.write(f"{prefix} ASCII: {ascii_dump}")
    logger.debug(f"{prefix} HEX: {hex_dump}")
    logger.debug(f"{prefix} ASCII: {ascii_dump}")

def find_all_occurrences(text, pattern):
    pos = 0
    occurrences = []
    while True:
        pos = text.find(pattern, pos)
        if pos == -1:
            break
        occurrences.append(pos)
        pos += 1
    logger.info(f"Trouvé {len(occurrences)} occurrences de {pattern}")
    return occurrences

def find_endstream(content, start_pos):
    """
    Recherche 'endstream' en tenant compte des différents formats possibles
    """
    logger.debug(f"Recherche de endstream à partir de la position {start_pos}")
    
    # Patterns possibles pour endstream (avec ou sans newline)
    patterns = [
        rb'endstream\r\n',
        rb'endstream\n',
        rb'endstream',
        b'endstream'
    ]
    
    min_pos = float('inf')
    for pattern in patterns:
        pos = content.find(pattern, start_pos)
        if pos != -1 and pos < min_pos:
            min_pos = pos
            logger.debug(f"Trouvé endstream pattern '{pattern}' à {pos}")
    
    if min_pos == float('inf'):
        logger.warning("Aucun endstream trouvé")
        return -1
    
    return min_pos

def process_drm(buffer, positions):
    processed = bytearray(buffer)
    
    for fopn_pos in positions:
        try:
            logger.info(f"Traitement de la position FOPN {fopn_pos}")
            
            # Extraire un contexte plus large
            start_pos = max(0, fopn_pos - 200)
            end_pos = min(len(buffer), fopn_pos + 2000)
            context = buffer[start_pos:end_pos]
            
            # Log du contexte en hex et ASCII pour debug
            logger.debug("Contexte autour de FOPN:")
            dump_buffer(buffer, start_pos, min(500, end_pos - start_pos), "CONTEXTE")
            
            # 1. Remplacer FOPN par FlateDecode
            logger.info(f"Remplacement FOPN à {fopn_pos}")
            processed[fopn_pos:fopn_pos+18] = b'/Filter/FlateDecode'
            
            # 2. Trouver et modifier V=1
            v_pattern = b'/V 1'
            v_pos = buffer[fopn_pos:end_pos].find(v_pattern)
            if v_pos != -1:
                abs_v_pos = fopn_pos + v_pos + 3
                logger.info(f"Modification V=1 à {abs_v_pos}")
                processed[abs_v_pos] = ord('0')
            else:
                logger.warning(f"V=1 non trouvé après FOPN {fopn_pos}")
            
            # 3. Trouver et effacer le stream chiffré
            info_pattern = b'/INFO('
            info_pos = buffer[fopn_pos:end_pos].find(info_pattern)
            if info_pos != -1:
                abs_info_pos = fopn_pos + info_pos
                logger.info(f"INFO trouvé à {abs_info_pos}")
                
                # Chercher endstream avec la nouvelle fonction
                stream_end = find_endstream(buffer, abs_info_pos)
                if stream_end != -1:
                    logger.info(f"Effacement stream {abs_info_pos}-{stream_end}")
                    dump_buffer(buffer, abs_info_pos, min(100, stream_end - abs_info_pos), "STREAM-AVANT")
                    processed[abs_info_pos:stream_end] = b'\x00' * (stream_end - abs_info_pos)
                else:
                    logger.error(f"endstream non trouvé après INFO à {abs_info_pos}")
                    st.warning(f"Stream non effacé à {abs_info_pos} (endstream non trouvé)")
            else:
                logger.warning(f"INFO non trouvé après FOPN {fopn_pos}")
                
        except Exception as e:
            logger.error(f"Erreur position {fopn_pos}: {str(e)}")
            st.error(f"Erreur position {fopn_pos}: {str(e)}")
            continue
            
    return bytes(processed)

def extract_text_from_pdf(buffer):
    try:
        # Tentative d'extraction avec options supplémentaires
        pdf_reader = PyPDF2.PdfReader(
            io.BytesIO(buffer),
            strict=False  # Mode moins strict
        )
        
        logger.info(f"PDF ouvert avec succès, {len(pdf_reader.pages)} pages")
        text = []
        
        for i, page in enumerate(pdf_reader.pages):
            try:
                page_text = page.extract_text()
                text.append(f"=== Page {i+1} ===\n{page_text}")
                logger.info(f"Page {i+1} extraite avec succès")
            except Exception as e:
                logger.error(f"Erreur extraction page {i+1}: {str(e)}")
                text.append(f"=== Page {i+1} ===\n[Erreur extraction]")
                continue
                
        return '\n\n'.join(text)
        
    except Exception as e:
        logger.error(f"Erreur extraction globale: {str(e)}")
        return None

def analyze_pdf(file_bytes):
    logger.info("=== DÉBUT ANALYSE PDF ===")
    st.write("=== DÉBUT ANALYSE PDF ===")
    
    file_size = len(file_bytes)
    logger.info(f"Taille: {file_size} bytes")
    st.write(f"Taille: {file_size} bytes")
    
    if file_bytes[:4] != b'%PDF':
        logger.error("Signature PDF invalide")
        raise ValueError("Format invalide")
    
    # Analyser la version du PDF
    version = file_bytes[5:8].decode('ascii', errors='ignore')
    logger.info(f"Version PDF: {version}")
    
    content = file_bytes.decode('latin-1', errors='ignore')
    matches = find_all_occurrences(content, '/FOPN_foweb')
    
    if not matches:
        st.write("Pas de protection")
        return {'has_fileopen': False}, file_bytes, extract_text_from_pdf(file_bytes)
    
    st.write(f"\n{len(matches)} protection(s) trouvée(s)")
    for i, pos in enumerate(matches):
        st.write(f"\nOccurrence {i+1} à {pos}")
        context = content[pos:pos+200]
        st.write(f"Contexte: {context}")
        
    processed = process_drm(file_bytes, matches)
    
    # Vérifier le PDF traité
    logger.info("Vérification du PDF traité")
    with open("temp.pdf", "wb") as f:
        f.write(processed)
    
    return {
        'has_fileopen': True,
        'type': 'FileOpen DRM',
        'filter': 'FOPN_foweb',
        'key_length': '5 bytes',
        'file_size': file_size,
        'size_kb': round(file_size / 1024)
    }, processed, extract_text_from_pdf(processed)

def main():
    st.set_page_config(page_title="DRM FileOpen", layout="wide")
    st.title("DRM FileOpen")
    
    files = st.file_uploader("PDF à traiter", type=['pdf'], accept_multiple_files=True)
    
    for file in files:
        try:
            logger.info(f"\n=== Traitement de {file.name} ===")
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
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.download_button("📄 Texte", text,
                            f"{file.name}_text.txt", "text/plain")
                    with col2:
                        st.download_button("📝 Fichier brut", bytes_data,
                            f"{file.name}_raw.txt", "text/plain")
                    with col3:
                        st.download_button("📄 PDF déprotégé", processed,
                            f"{file.name}_unprotected.pdf", "application/pdf")
                else:
                    st.error("Extraction du texte impossible")
                    st.download_button("📄 PDF déprotégé", processed,
                            f"{file.name}_unprotected.pdf", "application/pdf")
        
        except Exception as e:
            logger.error(f"Erreur: {str(e)}")
            st.error(f"Erreur: {str(e)}")

if __name__ == "__main__":
    main()
