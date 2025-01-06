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

# Configuration du logging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialisation de l'API OpenAI avec la clé depuis les secrets
@st.cache_resource
def get_openai_client():
    try:
        openai_api_key = st.secrets["openai_api_key"]
        return OpenAI(api_key=openai_api_key)
    except Exception as e:
        logger.error(f"Erreur d'initialisation OpenAI: {str(e)}")
        return None

def cache_key(context):
    """Génère une clé de cache unique pour le contexte"""
    return hashlib.md5(context.encode()).hexdigest()

@st.cache_data(ttl=3600)  # Cache pour 1 heure
def analyze_with_openai(context_hex, context_ascii, obj_number=None):
    """Analyse le contexte du DRM avec OpenAI avec cache"""
    try:
        client = get_openai_client()
        if not client:
            st.warning("OpenAI API non disponible - utilisation du mode standard")
            return None

        # Formatage du prompt avec les données de contexte et le numéro d'objet
        prompt = f"""Analyze this PDF DRM context from object {obj_number} and provide modification instructions:

HEX context: {context_hex[:300]}
ASCII context: {context_ascii[:300]}

Find these elements in the context:
1. The exact position of '/FOPN_foweb'
2. The '/V 1' attribute position and value
3. The stream beginning (after /INFO) and 'endstream' marker
4. Any other DRM-related attributes

Provide a JSON response with:
1. Positions and lengths of blocks to modify
2. Recommended replacement values
3. Stream boundaries
4. Any warnings or special handling needed

Format your response as valid JSON like this example:
{
    "modifications": [
        {
            "type": "filter",
            "start": 123,
            "length": 18,
            "replace_with": "/Filter/FlateDecode"
        }
    ],
    "stream": {
        "start": 456,
        "end": 789,
        "requires_zero_fill": true
    },
    "warnings": ["Check endstream marker at..."]
}"""

        messages = [
            {
                "role": "system",
                "content": "You are a PDF security expert. Analyze DRM structures and provide precise modification instructions in JSON format only."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            response_format={ "type": "json_object" },
            temperature=0
        )
        
        analysis = response.choices[0].message.content
        try:
            # Valider que c'est du JSON valide
            return json.loads(analysis)
        except json.JSONDecodeError:
            logger.error("Réponse OpenAI non valide JSON")
            return None
        
    except Exception as e:
        logger.error(f"Erreur OpenAI: {str(e)}")
        return None

def extract_object_number(context):
    """Extrait le numéro d'objet PDF du contexte"""
    try:
        obj_match = re.search(r'(\d+)\s+0\s+obj', context)
        if obj_match:
            return obj_match.group(1)
        return None
    except Exception:
        return None

def process_drm_with_ai(buffer, positions):
    processed = bytearray(buffer)
    modifications_log = []
    
    for fopn_pos in positions:
        try:
            # Extraire le contexte avec une marge plus large
            start_pos = max(0, fopn_pos - 200)
            end_pos = min(len(buffer), fopn_pos + 2000)
            context = buffer[start_pos:end_pos]
            
            # Préparer les données pour l'analyse
            hex_dump = ' '.join([f"{b:02x}" for b in context])
            ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in context])
            
            # Extraire le numéro d'objet pour le contexte
            obj_number = extract_object_number(ascii_dump)
            
            # Log du contexte
            logger.debug(f"Analyse de l'objet {obj_number} à la position {fopn_pos}")
            logger.debug(f"Contexte HEX: {hex_dump[:100]}...")
            
            # Obtenir l'analyse d'OpenAI
            analysis = analyze_with_openai(hex_dump, ascii_dump, obj_number)
            
            if analysis:
                st.write("📊 Analyse OpenAI :")
                st.json(analysis)
                
                # Appliquer les modifications suggérées
                for mod in analysis.get('modifications', []):
                    try:
                        abs_start = fopn_pos + (mod.get('start', 0) - 200)  # Ajuster avec l'offset du contexte
                        length = mod.get('length', 0)
                        replace_with = mod.get('replace_with', '').encode('ascii')
                        
                        if 0 <= abs_start < len(processed) and length > 0:
                            modifications_log.append({
                                'position': abs_start,
                                'type': mod.get('type'),
                                'original': processed[abs_start:abs_start+length].hex(),
                                'replacement': replace_with.hex()
                            })
                            processed[abs_start:abs_start+length] = replace_with.ljust(length, b'\x00')
                            logger.info(f"Modification appliquée: {mod['type']} à {abs_start}")
                
                # Traiter le stream si détecté
                stream_info = analysis.get('stream', {})
                if stream_info:
                    stream_start = fopn_pos + (stream_info.get('start', 0) - 200)
                    stream_end = fopn_pos + (stream_info.get('end', 0) - 200)
                    
                    if 0 <= stream_start < stream_end < len(processed):
                        if stream_info.get('requires_zero_fill', True):
                            processed[stream_start:stream_end] = b'\x00' * (stream_end - stream_start)
                            logger.info(f"Stream effacé: {stream_start}-{stream_end}")
                
                # Afficher les avertissements
                for warning in analysis.get('warnings', []):
                    st.warning(f"⚠️ {warning}")
                    
            else:
                # Fallback au traitement standard si OpenAI échoue
                logger.warning("Utilisation du traitement standard (OpenAI non disponible)")
                processed[fopn_pos:fopn_pos+18] = b'/Filter/FlateDecode'
                
                v_pos = buffer[fopn_pos:end_pos].find(b'/V 1')
                if v_pos != -1:
                    abs_v_pos = fopn_pos + v_pos + 3
                    processed[abs_v_pos] = ord('0')
                
                info_pos = buffer[fopn_pos:end_pos].find(b'/INFO(')
                if info_pos != -1:
                    stream_start = fopn_pos + info_pos
                    stream_end = buffer[stream_start:end_pos].find(b'endstream')
                    if stream_end != -1:
                        abs_stream_end = stream_start + stream_end
                        processed[stream_start:abs_stream_end] = b'\x00' * (abs_stream_end - stream_start)
            
        except Exception as e:
            logger.error(f"Erreur traitement position {fopn_pos}: {str(e)}")
            logger.error(traceback.format_exc())
            st.error(f"⚠️ Erreur position {fopn_pos}: {str(e)}")
            continue
    
    # Log des modifications
    if modifications_log:
        st.write("📝 Journal des modifications :")
        for mod in modifications_log:
            st.code(f"Position {mod['position']} ({mod['type']}): {mod['original']} -> {mod['replacement']}")
    
    return bytes(processed)

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
    st.title("🔓 DRM FileOpen")
    
    # Vérification de la configuration OpenAI
    client = get_openai_client()
    if not client:
        st.warning("⚠️ API OpenAI non configurée - mode standard actif")
    else:
        st.success("✅ API OpenAI connectée")
    
    # Interface utilisateur
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
                        
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.download_button("📄 Texte", text,
                                f"{file.name}_text.txt", "text/plain")
                        with col2:
                            st.download_button("📝 Fichier brut", bytes_data,
                                f"{file.name}_raw.txt", "text/plain")
                        with col3:
                            st.download_button("🔓 PDF déprotégé", processed,
                                f"{file.name}_unprotected.pdf", "application/pdf")
                        with col4:
                            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                            log_content = json.dumps(modifications_log, indent=2)
                            st.download_button("📊 Journal", log_content,
                                f"{file.name}_log_{timestamp}.json", "application/json")
                    else:
                        st.error("❌ Extraction du texte impossible")
                        st.download_button("🔓 PDF déprotégé", processed,
                            f"{file.name}_unprotected.pdf", "application/pdf")
            
            except Exception as e:
                logger.error(traceback.format_exc())
                st.error(f"❌ Erreur: {str(e)}")

if __name__ == "__main__":
    main()
