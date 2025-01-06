import streamlit as st
import io
import logging
from pathlib import Path
import PyPDF2
from openai import OpenAI
import json
import hashlib
from datetime import datetime
import traceback
import re

# Configuration du logging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@st.cache_resource
def get_openai_client():
    try:
        client = OpenAI(api_key=st.secrets["openai_api_key"])
        return client
    except Exception as e:
        logger.error(f"Erreur d'initialisation OpenAI: {str(e)}")
        return None

@st.cache_data(ttl=3600)
def analyze_drm_with_openai(context_hex, context_ascii, obj_number):
    try:
        client = get_openai_client()
        if not client:
            return None

        prompt = f"""Analyse ce contexte PDF qui contient une protection DRM FileOpen et fournis des instructions précises pour sa suppression.

Contexte:
Objet PDF: {obj_number}
HEX: {context_hex[:300]}
ASCII: {context_ascii[:300]}

Analyse nécessaire:
1. Localise les éléments clés:
   - Position exacte de '/FOPN_foweb'
   - Position de '/V 1'
   - Début et fin du stream chiffré (après /INFO jusqu'à endstream)
   - Autres attributs de DRM importants

2. Définis les modifications à appliquer:
   - Quels blocs doivent être modifiés
   - Valeurs de remplacement exactes
   - Taille des blocs à remplacer"""

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "Tu es un expert en analyse de PDF et DRM. Analyse les structures DRM et fournis des instructions de modification précises uniquement au format JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            response_format={ "type": "json_object" },
            temperature=0
        )
        
        try:
            return json.loads(response.choices[0].message.content)
        except json.JSONDecodeError:
            logger.error("Réponse OpenAI non valide")
            return None
            
    except Exception as e:
        logger.error(f"Erreur analyse OpenAI: {str(e)}")
        return None

def process_drm_with_ai(buffer, positions):
    processed = bytearray(buffer)
    modifications_log = []
    
    for fopn_pos in positions:
        try:
            # Extrait le contexte
            start_pos = max(0, fopn_pos - 200)
            end_pos = min(len(buffer), fopn_pos + 2000)
            context = buffer[start_pos:end_pos]
            
            # Prépare les données
            hex_dump = ' '.join([f"{b:02x}" for b in context])
            ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in context])
            obj_number = extract_object_number(ascii_dump)
            
            # Obtient l'analyse d'OpenAI
            analysis = analyze_drm_with_openai(hex_dump, ascii_dump, obj_number)
            
            if analysis:
                st.write("📊 Analyse DRM OpenAI:")
                st.json(analysis)
                
                try:
                    # Applique les modifications
                    for mod in analysis.get('modifications', []):
                        pos = fopn_pos + mod.get('position', 0)
                        length = mod.get('longueur', 0)
                        new_value = mod.get('valeur', '').encode('ascii')
                        
                        if 0 <= pos < len(processed) and length > 0:
                            modifications_log.append({
                                'position': pos,
                                'type': mod.get('type'),
                                'original': processed[pos:pos+length].hex(),
                                'new': new_value.hex()
                            })
                            processed[pos:pos+length] = new_value.ljust(length, b'\x00')
                            logger.info(f"Modification appliquée: {mod['type']} à {pos}")

                    # Traite le stream
                    stream = analysis.get('stream', {})
                    if stream:
                        start = fopn_pos + stream.get('debut', 0)
                        end = fopn_pos + stream.get('fin', 0)
                        
                        if 0 <= start < end < len(processed):
                            if stream.get('effacement_necessaire', True):
                                processed[start:end] = b'\x00' * (end - start)
                                logger.info(f"Stream effacé: {start}-{end}")

                    # Affiche les avertissements
                    for warning in analysis.get('warnings', []):
                        st.warning(f"⚠️ {warning}")
                except Exception as e:
                    logger.error(f"Erreur application modifications: {str(e)}")
                    st.error(f"Erreur modifications: {str(e)}")
            
            else:
                # Mode standard si OpenAI échoue
                st.warning("Mode standard activé (OpenAI indisponible)")
                logger.warning("Utilisation du mode standard")
                try:
                    processed[fopn_pos:fopn_pos+18] = b'/Filter/FlateDecode'
                    
                    v_pos = buffer[fopn_pos:end_pos].find(b'/V 1')
                    if v_pos != -1:
                        v_abs = fopn_pos + v_pos + 3
                        processed[v_abs] = ord('0')
                        
                    info_pos = buffer[fopn_pos:end_pos].find(b'/INFO(')
                    if info_pos != -1:
                        stream_start = fopn_pos + info_pos
                        stream_end = buffer[stream_start:end_pos].find(b'endstream')
                        if stream_end != -1:
                            abs_stream_end = stream_start + stream_end
                            processed[stream_start:abs_stream_end] = b'\x00' * (abs_stream_end - stream_start)
                except Exception as e:
                    logger.error(f"Erreur mode standard: {str(e)}")
                    st.error(f"Erreur mode standard: {str(e)}")
        
        except Exception as e:
            logger.error(f"Erreur position {fopn_pos}: {str(e)}")
            logger.error(traceback.format_exc())
            st.error(f"⚠️ Erreur position {fopn_pos}: {str(e)}")
            continue
    
    return bytes(processed)

def extract_object_number(context):
    """Extrait le numéro d'objet PDF du contexte"""
    try:
        obj_match = re.search(r'(\d+)\s+0\s+obj', context)
        if obj_match:
            return obj_match.group(1)
        return None
    except Exception:
        return None

def find_all_occurrences(text, pattern):
    """Trouve toutes les occurrences d'un pattern dans le texte"""
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

def extract_text_from_pdf(buffer):
    """Extrait le texte du PDF"""
    try:
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(buffer), strict=False)
        text = []
        for i, page in enumerate(pdf_reader.pages):
            try:
                text.append(f"=== Page {i+1} ===\n{page.extract_text()}")
                logger.info(f"Page {i+1} extraite avec succès")
            except Exception as e:
                logger.error(f"Erreur extraction page {i+1}: {str(e)}")
                text.append(f"=== Page {i+1} ===\n[Erreur extraction]")
        return '\n\n'.join(text)
    except Exception as e:
        logger.error(f"Erreur extraction globale: {str(e)}")
        return None

def analyze_pdf(file_bytes):
    """Analyse principale du PDF avec support OpenAI"""
    logger.info("=== DÉBUT ANALYSE PDF ===")
    st.write("=== DÉBUT ANALYSE PDF ===")
    
    if not file_bytes[:4] == b'%PDF':
        raise ValueError("Format PDF invalide")
    
    # Informations de base
    file_info = {
        'size': len(file_bytes),
        'version': file_bytes[5:8].decode('ascii', errors='ignore'),
        'has_fileopen': False
    }
    
    content = file_bytes.decode('latin-1', errors='ignore')
    matches = list(find_all_occurrences(content, '/FOPN_foweb'))
    
    if not matches:
        logger.info("Aucune protection détectée")
        return file_info, file_bytes, extract_text_from_pdf(file_bytes)
    
    file_info.update({
        'has_fileopen': True,
        'type': 'FileOpen DRM',
        'filter': 'FOPN_foweb',
        'key_length': '5 bytes',
        'size_kb': round(len(file_bytes) / 1024),
        'protection_count': len(matches)
    })
    
    processed = process_drm_with_ai(file_bytes, matches)
    text = extract_text_from_pdf(processed)
    
    return file_info, processed, text

def main():
    st.set_page_config(page_title="DRM FileOpen", layout="wide")
    st.title("🔓 DRM FileOpen Analyzer")
    
    # Vérification de la configuration OpenAI
    client = get_openai_client()
    if not client:
        st.warning("⚠️ API OpenAI non configurée - mode standard actif")
    else:
        st.success("✅ API OpenAI connectée")
    
    files = st.file_uploader("PDF à traiter", type=['pdf'], accept_multiple_files=True)
    
    if files:
        for file in files:
            try:
                st.write(f"\n=== 📄 {file.name} ===")
                bytes_data = file.getvalue()
                
                with st.spinner("Analyse en cours..."):
                    info, processed, text = analyze_pdf(bytes_data)
                
                # Affichage des métriques
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Protection", info.get('type', 'Aucune'))
                    st.metric("Filtre", info.get('filter', 'N/A'))
                with col2:
                    st.metric("Clé", info.get('key_length', 'N/A'))
                    st.metric("Taille", f"{info.get('size_kb', 0)} KB")
                with col3:
                    st.metric("Version PDF", info.get('version', 'N/A'))
                    if info.get('protection_count'):
                        st.metric("Protections", info['protection_count'])
                
                # Résultats et boutons de téléchargement
                if info['has_fileopen']:
                    st.warning("🔓 Protection FileOpen détectée et déprotégée")
                    
                    if text:
                        with st.expander("📝 Texte extrait"):
                            st.text_area("Contenu", text, height=200)
                        
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.download_button("📄 Texte", text,
                                f"{file.name}_text.txt", "text/plain")
                        with col2:
                            st.download_button("📝 Fichier brut", bytes_data,
                                f"{file.name}_raw.txt", "text/plain")
                        with col3:
                            st.download_button("🔓 PDF déprotégé", processed,
                                f"{file.name}_unprotected.pdf", "application/pdf")
                    else:
                        st.error("❌ Extraction du texte impossible")
                        st.download_button("🔓 PDF déprotégé", processed,
                            f"{file.name}_unprotected.pdf", "application/pdf")
            
            except Exception as e:
                logger.error(traceback.format_exc())
                st.error(f"❌ Erreur: {str(e)}")

if __name__ == "__main__":
    main()
