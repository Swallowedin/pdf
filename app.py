import streamlit as st
import io
import logging
from pathlib import Path
import PyPDF2
import traceback

# Configuration du logging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def dump_buffer(buffer, start, length, prefix=""):
    hex_dump = ' '.join([f"{b:02x}" for b in buffer[start:start+length]])
    ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in buffer[start:start+length]])
    logger.debug(f"{prefix} HEX: {hex_dump}")
    logger.debug(f"{prefix} ASCII: {ascii_dump}")
    st.write(f"{prefix} HEX: {hex_dump}")
    st.write(f"{prefix} ASCII: {ascii_dump}")

def find_all_occurrences(text, pattern):
    logger.debug(f"Recherche du pattern '{pattern}' dans le texte")
    pos = 0
    occurrences = 0
    while True:
        pos = text.find(pattern, pos)
        if pos == -1:
            break
        logger.debug(f"Pattern trouvé à la position {pos}")
        occurrences += 1
        yield pos
        pos += 1
    logger.debug(f"Total des occurrences trouvées: {occurrences}")

def process_drm(buffer, positions):
    logger.info("Début du traitement DRM")
    processed = bytearray(buffer)
    
    for pos in positions:
        try:
            logger.debug(f"Traitement de la position {pos}")
            # 1. Trouver le bloc FileOpen
            context = buffer[pos:pos+1000].decode('latin-1', errors='ignore')
            logger.debug(f"Contexte autour de la position {pos}: {context[:100]}...")
            
            # 2. Remplacer FOPN par FlateDecode
            try:
                processed[pos:pos+18] = b'/Filter/FlateDecode'
                logger.info(f"Filtre remplacé avec succès à {pos}")
            except Exception as e:
                logger.error(f"Erreur lors du remplacement du filtre à {pos}: {str(e)}")
                st.error(f"Erreur remplacement filtre: {str(e)}")
                raise
            
            # 3. Changer V=1 en V=0
            v_pos = context.find('/V 1')
            if v_pos != -1:
                v_abs = pos + v_pos + 3
                try:
                    processed[v_abs] = ord('0')
                    logger.info(f"V modifié avec succès à {v_abs}")
                except Exception as e:
                    logger.error(f"Erreur lors de la modification de V à {v_abs}: {str(e)}")
                    st.error(f"Erreur modification V: {str(e)}")
                    raise
            else:
                logger.warning(f"'/V 1' non trouvé dans le contexte à {pos}")
            
            # 4. Remplacer le stream chiffré
            info_pos = context.find('/INFO(')
            if info_pos != -1:
                try:
                    stream_start = pos + info_pos
                    stream_end = stream_start + context[info_pos:].find('endstream')
                    logger.debug(f"Stream trouvé: début={stream_start}, fin={stream_end}")
                    if stream_end > stream_start:
                        processed[stream_start:stream_end] = b'\x00' * (stream_end - stream_start)
                        logger.info(f"Stream effacé avec succès: {stream_start}-{stream_end}")
                    else:
                        logger.error(f"Positions de stream invalides: début={stream_start}, fin={stream_end}")
                        raise ValueError("Positions de stream invalides")
                except Exception as e:
                    logger.error(f"Erreur lors du traitement du stream: {str(e)}")
                    st.error(f"Erreur traitement stream: {str(e)}")
                    raise
            else:
                logger.warning(f"'/INFO(' non trouvé dans le contexte à {pos}")
                
        except Exception as e:
            logger.error(f"Erreur lors du traitement de la position {pos}: {str(e)}")
            logger.error(traceback.format_exc())
            st.error(f"Erreur position {pos}: {str(e)}")
            raise
            
    logger.info("Fin du traitement DRM")
    return bytes(processed)

def extract_text_from_pdf(buffer):
    logger.info("Début de l'extraction du texte")
    try:
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(buffer))
        logger.debug(f"Nombre de pages: {len(pdf_reader.pages)}")
        text = []
        for i, page in enumerate(pdf_reader.pages):
            logger.debug(f"Extraction du texte de la page {i+1}")
            try:
                page_text = page.extract_text()
                text.append(f"=== Page {i+1} ===\n{page_text}")
                logger.debug(f"Page {i+1} extraite avec succès ({len(page_text)} caractères)")
            except Exception as e:
                logger.error(f"Erreur extraction page {i+1}: {str(e)}")
                st.error(f"Erreur page {i+1}: {str(e)}")
        return '\n\n'.join(text)
    except Exception as e:
        logger.error(f"Erreur extraction globale: {str(e)}")
        logger.error(traceback.format_exc())
        st.error(f"Erreur extraction: {str(e)}")
        return None

def analyze_pdf(file_bytes):
    logger.info("=== DÉBUT ANALYSE PDF ===")
    st.write("=== DÉBUT ANALYSE PDF ===")
    
    logger.debug(f"Taille du fichier: {len(file_bytes)} bytes")
    logger.debug(f"Signature: {file_bytes[:8].hex()}")
    st.write(f"Taille: {len(file_bytes)} bytes")
    st.write(f"Signature: {file_bytes[:8].hex()}")
    
    if file_bytes[:4] != b'%PDF':
        logger.error("Format PDF invalide")
        raise ValueError("Format invalide")
    
    try:
        content = file_bytes.decode('latin-1', errors='ignore')
        matches = list(find_all_occurrences(content, '/FOPN_foweb'))
        
        if not matches:
            logger.info("Aucune protection détectée")
            st.write("Pas de protection")
            return {'has_fileopen': False}, file_bytes, extract_text_from_pdf(file_bytes)
        
        logger.info(f"{len(matches)} protection(s) FileOpen trouvée(s)")
        st.write(f"\n{len(matches)} protection(s) trouvée(s)")
        
        for i, pos in enumerate(matches):
            logger.debug(f"Occurrence {i+1} à la position {pos}")
            context = content[pos:pos+200]
            logger.debug(f"Contexte: {context}")
            st.write(f"\nOccurrence {i+1} à {pos}")
            st.write(f"Contexte: {context}")
        
        processed = process_drm(file_bytes, matches)
        logger.info("Traitement DRM terminé avec succès")
        
        return {
            'has_fileopen': True,
            'type': 'FileOpen DRM',
            'filter': 'FOPN_foweb',
            'key_length': '5 bytes',
            'file_size': len(file_bytes),
            'size_kb': round(len(file_bytes) / 1024)
        }, processed, extract_text_from_pdf(processed)
        
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse: {str(e)}")
        logger.error(traceback.format_exc())
        raise

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
                logger.info("Protection FileOpen détectée et déprotégée")
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
        
        except Exception as e:
            logger.error(f"Erreur globale: {str(e)}")
            logger.error(traceback.format_exc())
            st.error(f"Erreur: {str(e)}")

if __name__ == "__main__":
    main()
